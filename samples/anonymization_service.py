"""Anonymization service (V2-S4 sub-task 21d).

13-month inactivity-based anonymization lifecycle.

STAGE 1 (300d): 90-day warning email
STAGE 2 (365d): 30-day warning + keep_active link
STAGE 3 (388d): 7-day final warning + keep_active link
STAGE 4 (395d): PII anonymization + Stripe cancel + shop deactivation
STAGE 5 (575d): hard delete anonymized users + cascade shops/products/MinIO

Architectural decisions:
- No ABC pattern (direct DI via __init__)
- frontend_url: str parameter (no Settings dependency)
- Active subscribers excluded from ALL stages
- Stage 4 atomic per-user commit
- hash_email() captured BEFORE PII wipe
- stripe_customer_id PRESERVED (VAT 5-year retention)
- shop.domain anonymized to anonymized-shop-{id}.local
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import create_keep_active_token, hash_email
from sqlalchemy.orm import selectinload
from models.anonymization_log import AnonymizationLog
from models.consent import ConsentRecord
from models.shop import Shop
from models.user import User
from services.billing_teardown import cancel_with_reconciliation
from services.email_service import EmailSendError, EmailService, get_email_service
from services.email_templates import (
    render_anonymization_warning_30d_email,
    render_anonymization_warning_7d_email,
    render_anonymization_warning_90d_email,
)
from services.payment_service import PaymentService, get_payment_service
from services.storage.factory import get_image_storage

logger = logging.getLogger(__name__)

_WARN_90D_THRESHOLD = 300
_WARN_30D_THRESHOLD = 365
_WARN_7D_THRESHOLD = 388
_ANONYMIZE_THRESHOLD = 395
_HARD_DELETE_THRESHOLD = 180  # days after anonymized_at (Stage 5)


class StripeBreakdown(BaseModel):
    """Per-shop Stripe cancellation outcomes within a Stage 4 run.

    T2 monitoring: cron yml parses this JSON via jq to compute error rate
    and emit ::error:: alert if failed/(succeeded+already_canceled+failed) > 20%.
    """

    succeeded: int = 0
    already_canceled: int = 0
    failed: int = 0


class AnonymizationRunResult(BaseModel):
    """Aggregate result of AnonymizationService.run()."""

    stage_1_warned: int = 0
    stage_2_warned: int = 0
    stage_3_warned: int = 0
    stage_4_anonymized: int = 0
    stage_5_hard_deleted: int = 0
    stripe_breakdown: StripeBreakdown = StripeBreakdown()
    duration_ms: float = 0.0
    errors: list[str] = []


class AnonymizationService:
    """GDPR inactivity-based anonymization service. 4-stage state machine.

    Called daily at 03:00 UTC by GitHub Actions (anonymization-cron.yml).
    """

    def __init__(
        self,
        *,
        session: AsyncSession,
        email_service: EmailService,
        payment_service: PaymentService,
        redis: Redis,
        frontend_url: str,
        storage=None,  # Optional[ImageStorage] — wired in Stage 5 GREEN phase
    ) -> None:
        self._session = session
        self._email_service = email_service
        self._payment_service = payment_service
        self._redis = redis
        self._frontend_url = frontend_url
        self._storage = storage

    async def run(self) -> AnonymizationRunResult:
        """Execute all 4 stages sequentially. Returns aggregate result.

        run_start_time is captured once before Stage 1. Stages 2/3 use it to
        prevent cascading within a single run (a user warned by Stage N in this
        run is NOT immediately processed by Stage N+1 in the same run).

        Each stage's failures are isolated (best-effort) — Stage N
        unexpected exception does not abort Stage N+1.
        """
        start = time.monotonic()
        run_start_time = datetime.now(timezone.utc)
        result = AnonymizationRunResult()

        # Stages 1, 2, 3 — return int count
        for stage_num, stage_method, count_field in [
            (1, lambda: self.run_stage_1_warn_90d(run_start_time), "stage_1_warned"),
            (2, lambda: self.run_stage_2_warn_30d(run_start_time), "stage_2_warned"),
            (3, lambda: self.run_stage_3_warn_7d(run_start_time), "stage_3_warned"),
        ]:
            try:
                count = await stage_method()
                setattr(result, count_field, count)
            except Exception as exc:
                err_msg = f"Stage {stage_num} unexpected error: {exc}"
                logger.error(err_msg, exc_info=True)
                result.errors.append(err_msg)

        # Stage 4 — returns (count, breakdown) — handled separately for T2 monitoring
        try:
            count, breakdown = await self.run_stage_4_anonymize(run_start_time)
            result.stage_4_anonymized = count
            result.stripe_breakdown = breakdown
        except Exception as exc:
            err_msg = f"Stage 4 unexpected error: {exc}"
            logger.error(err_msg, exc_info=True)
            result.errors.append(err_msg)

        # Stage 5 — returns int count
        try:
            result.stage_5_hard_deleted = await self.run_stage_5_hard_delete(run_start_time)
        except Exception as exc:
            err_msg = f"Stage 5 unexpected error: {exc}"
            logger.error(err_msg, exc_info=True)
            result.errors.append(err_msg)

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def _build_active_subscriber_subquery(self):
        """SQL EXISTS subquery: user has at least one shop with a live subscription.

        N19: "live" = {active, trialing, past_due} — trialing/past_due are still
        paying (or about-to-pay) customers, not just fully-active ones. Shared
        by Stages 1-4, so a live-subscription user is excluded from warnings
        AND anonymization alike.
        """
        return (
            select(Shop.id)
            .where(
                Shop.owner_id == User.id,
                Shop.subscription_status.in_(("active", "trialing", "past_due")),
            )
            .correlate(User)
            .exists()
        )

    async def run_stage_1_warn_90d(self, run_start_time: datetime) -> int:
        """Send 90-day warning to users inactive > 300 days."""
        now = datetime.now(timezone.utc)
        active_sub = self._build_active_subscriber_subquery()

        result = await self._session.execute(
            select(User).where(
                and_(
                    func.coalesce(User.last_login_at, User.created_at) < now - timedelta(days=_WARN_90D_THRESHOLD),
                    User.anonymization_warned_90d_at.is_(None),
                    User.is_anonymized.is_(False),
                    ~active_sub,
                )
            )
        )
        users = list(result.scalars().all())

        count = 0
        for user in users:
            user.anonymization_warned_90d_at = now
            self._session.add(user)

            html, text = render_anonymization_warning_90d_email(user.email)
            await self._send_email_safe(
                to=user.email,
                subject="Twoje konto wygaśnie za 90 dni — AI Smart Filters",
                html_body=html,
                text_body=text,
                user_id=user.id,
            )

            self._session.add(
                AnonymizationLog(
                    user_id=user.id,
                    action="warning_90d_sent",
                    user_email_hash=hash_email(user.email),
                    triggered_by="cron",
                    log_metadata={"stage": 1},
                )
            )

            count += 1

        await self._session.commit()
        return count

    async def run_stage_2_warn_30d(self, run_start_time: datetime) -> int:
        """Send 30-day warning + keep_active URL to users inactive > 365 days."""
        now = datetime.now(timezone.utc)
        active_sub = self._build_active_subscriber_subquery()

        result = await self._session.execute(
            select(User).where(
                and_(
                    func.coalesce(User.last_login_at, User.created_at) < now - timedelta(days=_WARN_30D_THRESHOLD),
                    User.anonymization_warned_90d_at.is_not(None),
                    User.anonymization_warned_90d_at < run_start_time,
                    User.anonymization_warned_30d_at.is_(None),
                    User.is_anonymized.is_(False),
                    ~active_sub,
                )
            )
        )
        users = list(result.scalars().all())

        count = 0
        for user in users:
            user.anonymization_warned_30d_at = now
            self._session.add(user)

            keep_active_url = await self._create_keep_active_url(user.id)

            html, text = render_anonymization_warning_30d_email(
                user_email=user.email,
                keep_active_url=keep_active_url,
            )
            await self._send_email_safe(
                to=user.email,
                subject="Konto wygaśnie za 30 dni — AI Smart Filters",
                html_body=html,
                text_body=text,
                user_id=user.id,
            )

            self._session.add(
                AnonymizationLog(
                    user_id=user.id,
                    action="warning_30d_sent",
                    user_email_hash=hash_email(user.email),
                    triggered_by="cron",
                    log_metadata={"stage": 2},
                )
            )

            count += 1

        await self._session.commit()
        return count

    async def run_stage_3_warn_7d(self, run_start_time: datetime) -> int:
        """Send 7-day FINAL warning + keep_active URL to users inactive > 388 days."""
        now = datetime.now(timezone.utc)
        active_sub = self._build_active_subscriber_subquery()

        result = await self._session.execute(
            select(User).where(
                and_(
                    func.coalesce(User.last_login_at, User.created_at) < now - timedelta(days=_WARN_7D_THRESHOLD),
                    User.anonymization_warned_30d_at.is_not(None),
                    User.anonymization_warned_30d_at < run_start_time,
                    User.anonymization_warned_7d_at.is_(None),
                    User.is_anonymized.is_(False),
                    ~active_sub,
                )
            )
        )
        users = list(result.scalars().all())

        count = 0
        for user in users:
            user.anonymization_warned_7d_at = now
            self._session.add(user)

            keep_active_url = await self._create_keep_active_url(user.id)

            html, text = render_anonymization_warning_7d_email(
                user_email=user.email,
                keep_active_url=keep_active_url,
            )
            await self._send_email_safe(
                to=user.email,
                subject="OSTATNIA SZANSA — konto wygaśnie za 7 dni — AI Smart Filters",
                html_body=html,
                text_body=text,
                user_id=user.id,
            )

            self._session.add(
                AnonymizationLog(
                    user_id=user.id,
                    action="warning_7d_sent",
                    user_email_hash=hash_email(user.email),
                    triggered_by="cron",
                    log_metadata={"stage": 3},
                )
            )

            count += 1

        await self._session.commit()
        return count

    async def run_stage_4_anonymize(
        self, run_start_time: datetime
    ) -> tuple[int, "StripeBreakdown"]:
        """Anonymize PII for users inactive > 395 days who received 7-day warning.

        Returns (anonymized_user_count, stripe_breakdown). Breakdown tracks
        per-shop Stripe outcomes (succeeded/already_canceled/failed) for T2
        monitoring — consumed by cron yml jq to compute error rate.
        """
        now = datetime.now(timezone.utc)
        active_sub = self._build_active_subscriber_subquery()

        result = await self._session.execute(
            select(User)
            .where(
                and_(
                    func.coalesce(User.last_login_at, User.created_at) < now - timedelta(days=_ANONYMIZE_THRESHOLD),
                    User.anonymization_warned_7d_at.is_not(None),
                    User.is_anonymized.is_(False),
                    ~active_sub,
                )
            )
            .limit(50)
            .options(selectinload(User.shops))
            .execution_options(populate_existing=True)
        )
        users = list(result.scalars().all())

        breakdown = StripeBreakdown()
        count = 0
        for user in users:
            # CRITICAL: capture BEFORE mutation (irreversible)
            email_hash = hash_email(user.email)
            shop_ids = [s.id for s in user.shops]

            # N19: cancel_with_reconciliation never raises — a failure after
            # retry is recorded in failed_stripe_cancellations (audit trail)
            # and reported here via "recorded_failure" so this user is
            # skipped THIS run rather than anonymized with an unresolved
            # (possibly still-live) subscription. Shops that DID cancel
            # successfully still have their sub_id cleared regardless — that
            # reflects reality at Stripe independent of the user's fate.
            user_has_unresolved_stripe = False
            for shop in user.shops:
                outcome = await cancel_with_reconciliation(
                    shop, self._session, self._payment_service
                )
                if outcome == "succeeded":
                    breakdown.succeeded += 1
                    shop.stripe_subscription_id = None
                elif outcome == "already_canceled":
                    breakdown.already_canceled += 1
                    shop.stripe_subscription_id = None
                elif outcome == "recorded_failure":
                    breakdown.failed += 1
                    user_has_unresolved_stripe = True
                # "no_subscription": nothing to track/clear.

            if user_has_unresolved_stripe:
                logger.warning(
                    "Stage4 skipping user_id=%s this run — Stripe cancel failed for "
                    "at least one shop (see failed_stripe_cancellations); not "
                    "anonymizing with an unresolved subscription",
                    user.id,
                )
                try:
                    # Persist cleared sub_ids (for shops that DID succeed) and the
                    # FailedStripeCancellation row(s) added above — no PII wipe.
                    await self._session.commit()
                except asyncio.CancelledError:
                    await self._session.rollback()
                    raise
                continue

            for shop in user.shops:
                shop.is_widget_active = False
                shop.subscription_status = "inactive"
                shop.domain = f"anonymized-shop-{shop.id}.local"
                # stripe_customer_id PRESERVED (5-year VAT retention)
                self._session.add(shop)

            # Wipe user PII
            user.email = f"deleted_{user.id}@anon.invalid"
            user.password_hash = ""
            user.anonymization_warned_90d_at = None
            user.anonymization_warned_30d_at = None
            user.anonymization_warned_7d_at = None
            user.is_anonymized = True
            user.anonymized_at = now
            self._session.add(user)

            # Audit log (uses pre-wipe hash — CRITICAL)
            self._session.add(
                AnonymizationLog(
                    user_id=user.id,
                    action="anonymized",
                    user_email_hash=email_hash,
                    triggered_by="cron",
                    log_metadata={"shop_ids": shop_ids},
                )
            )

            try:
                await self._session.commit()  # ATOMIC: wipe + log per user
            except asyncio.CancelledError:
                await self._session.rollback()
                raise
            count += 1

        return count, breakdown

    async def run_stage_5_hard_delete(self, run_start_time: datetime) -> int:
        """Hard delete anonymized users 6+ months after anonymization (Stage 5).

        Query: is_anonymized=True AND anonymized_at < now-180d AND < run_start_time.
        Cascade prevention: run_start_time guard prevents Stage 4 users from being
        immediately hard-deleted in the same cron run.

        Per user (atomic per-user commit):
        1. SELECT shops with products loaded (selectinload for MinIO key collection)
        2. N46: re-cancel Stripe subscription per shop (defense in depth — idempotent)
        3. Collect product.local_image_url keys BEFORE delete
        4. Add AnonymizationLog(action="hard_deleted") BEFORE delete (user_id NOT FK)
        5. DELETE shops → ORM cascade removes products/widget_config/sync_jobs
           DB cascade removes filter_configs/analytics automatically
        6. DELETE user
        7. commit() — atomic per user
        8. Post-commit MinIO cleanup (best-effort, sync, non-blocking on failure)
        """
        from models.shop import Shop

        now = datetime.now(timezone.utc)

        result = await self._session.execute(
            select(User).where(
                and_(
                    User.is_anonymized.is_(True),
                    User.anonymized_at < now - timedelta(days=_HARD_DELETE_THRESHOLD),
                    User.anonymized_at < run_start_time,
                )
            ).limit(50)
        )
        users = list(result.scalars().all())

        count = 0
        for user in users:
            shops_result = await self._session.execute(
                select(Shop)
                .where(Shop.owner_id == user.id)
                .options(selectinload(Shop.products))
            )
            shops = list(shops_result.scalars().all())

            # N46: re-cancel before hard-delete — defense in depth against a shop
            # resurrected by a late/stale webhook event after Stage-4 anonymized
            # it (a stripe_subscription_id could have been re-set since then).
            # Idempotent (already_canceled = OK); never blocks the hard delete —
            # a failure is recorded in failed_stripe_cancellations, no FK on
            # shop_id so the row survives the shop's deletion below.
            for shop in shops:
                await cancel_with_reconciliation(shop, self._session, self._payment_service)

            minio_keys: list[str] = []
            for shop in shops:
                for product in shop.products:
                    if product.local_image_url:
                        minio_keys.append(product.local_image_url)

            # F25: preserve NON-PII proof of consent (consent_type, document_version,
            # created_at — no plaintext email) BEFORE the CASCADE delete below removes
            # consent_records. user_id is NOT a FK on AnonymizationLog, so it survives.
            consent_result = await self._session.execute(
                select(ConsentRecord).where(ConsentRecord.user_id == user.id)
            )
            consent_proofs = [
                {
                    "consent_type": rec.consent_type,
                    "document_version": rec.document_version,
                    "created_at": rec.created_at.isoformat(),
                }
                for rec in consent_result.scalars().all()
            ]

            self._session.add(
                AnonymizationLog(
                    user_id=user.id,
                    action="hard_deleted",
                    user_email_hash=hash_email(user.email),
                    triggered_by="cron",
                    log_metadata={
                        "shop_ids": [s.id for s in shops],
                        "minio_keys_count": len(minio_keys),
                        "consent_proofs": consent_proofs,
                    },
                )
            )

            # C-25: delete MinIO objects BEFORE committing the DB deletion.
            # If the process crashes after commit but before MinIO delete, the
            # files are orphaned with no DB record.  Deleting first means a crash
            # before commit leaves the user in DB for retry next run.
            if self._storage is not None:
                for key in minio_keys:
                    try:
                        await asyncio.to_thread(self._storage.delete, key)
                    except Exception as exc:
                        logger.error(
                            "Stage5 MinIO cleanup failed key=%s: %s — continuing",
                            key,
                            exc,
                        )

            for shop in shops:
                await self._session.delete(shop)

            await self._session.delete(user)
            await self._session.commit()
            count += 1

        return count

    async def _create_keep_active_url(self, user_id: int) -> str:
        """Create one-time keep_active URL. Token stored in Redis with 7d TTL."""
        token = await create_keep_active_token(user_id, self._redis)
        return f"{self._frontend_url}/account/keep-active?token={token}"

    async def _send_email_safe(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        text_body: str,
        user_id: int,
    ) -> None:
        """Best-effort email send. Logs warning on EmailSendError, never raises."""
        try:
            await self._email_service.send_email(
                to=to,
                subject=subject,
                html_body=html_body,
                text_body=text_body,
            )
            logger.info("Email sent to user_id=%s", user_id)
        except EmailSendError as exc:
            logger.warning(
                "Failed to send email to user_id=%s: %s — continuing",
                user_id,
                exc,
            )
        except Exception as exc:
            # B1-3: network/transport errors (httpx.ConnectError, timeouts, etc.)
            # are best-effort — log and continue, do not abort the stage.
            # asyncio.CancelledError is BaseException and bypasses this clause.
            logger.warning(
                "Failed to send email to user_id=%s (network error): %s — continuing",
                user_id,
                exc,
            )


def build_anonymization_service(
    session: AsyncSession,
    redis: Redis,
    frontend_url: str,
    *,
    include_storage: bool = True,
) -> AnonymizationService:
    """Factory — eliminates diverged instantiation between admin route and worker cron.

    include_storage decision (F008/FW-C/2):
    - admin route: include_storage=True (default) — Stage 5 hard-deletes MinIO images.
    - worker cron: include_storage=False (explicit, behavior-preserving) — FW-C/3 enables.
    """
    return AnonymizationService(
        session=session,
        email_service=get_email_service(),
        payment_service=get_payment_service(),
        redis=redis,
        frontend_url=frontend_url,
        storage=get_image_storage() if include_storage else None,
    )
