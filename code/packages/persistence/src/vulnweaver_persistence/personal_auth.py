"""Persistence primitives for the installation's single personal account."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import RowMapping, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection

from vulnweaver_persistence.models import personal_accounts, personal_sessions


@dataclass(frozen=True, slots=True)
class PersonalAccount:
    username: str
    password_hash: str
    must_change_password: bool
    password_version: int
    failed_login_attempts: int
    locked_until: datetime | None


@dataclass(frozen=True, slots=True)
class PersonalSession:
    token_digest: str
    csrf_digest: str
    expires_at: datetime
    password_version: int


class PersonalAuthRepository:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def bootstrap(
        self, *, username: str, password_hash: str, must_change_password: bool
    ) -> bool:
        result = await self._connection.execute(
            insert(personal_accounts)
            .values(
                id="personal",
                username=username,
                password_hash=password_hash,
                must_change_password=must_change_password,
            )
            .on_conflict_do_nothing(index_elements=[personal_accounts.c.id])
            .returning(personal_accounts.c.id)
        )
        return result.scalar_one_or_none() is not None

    async def account_by_username(self, username: str) -> PersonalAccount | None:
        row = (
            (
                await self._connection.execute(
                    select(personal_accounts).where(personal_accounts.c.username == username)
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _account(row)

    async def record_login_failure(
        self, username: str, *, threshold: int, locked_until: datetime
    ) -> None:
        row = (
            (
                await self._connection.execute(
                    select(personal_accounts)
                    .where(personal_accounts.c.username == username)
                    .with_for_update()
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return
        attempts = int(row["failed_login_attempts"]) + 1
        await self._connection.execute(
            update(personal_accounts)
            .where(personal_accounts.c.id == "personal")
            .values(
                failed_login_attempts=attempts,
                locked_until=locked_until if attempts >= threshold else row["locked_until"],
            )
        )

    async def record_login_success(self) -> None:
        await self._connection.execute(
            update(personal_accounts)
            .where(personal_accounts.c.id == "personal")
            .values(failed_login_attempts=0, locked_until=None)
        )

    async def account(self) -> PersonalAccount | None:
        row = (
            (
                await self._connection.execute(
                    select(personal_accounts).where(personal_accounts.c.id == "personal")
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else _account(row)

    async def add_session(self, session: PersonalSession) -> None:
        await self._connection.execute(
            insert(personal_sessions).values(
                token_digest=session.token_digest,
                account_id="personal",
                csrf_digest=session.csrf_digest,
                password_version=session.password_version,
                expires_at=session.expires_at,
            )
        )

    async def resolve_session(
        self, token_digest: str
    ) -> tuple[PersonalAccount, PersonalSession] | None:
        row = (
            (
                await self._connection.execute(
                    select(
                        personal_accounts.c.username,
                        personal_accounts.c.password_hash,
                        personal_accounts.c.must_change_password,
                        personal_accounts.c.password_version.label("account_password_version"),
                        personal_accounts.c.failed_login_attempts,
                        personal_accounts.c.locked_until,
                        personal_sessions.c.token_digest,
                        personal_sessions.c.csrf_digest,
                        personal_sessions.c.expires_at,
                        personal_sessions.c.password_version.label("session_password_version"),
                    )
                    .join(
                        personal_sessions, personal_sessions.c.account_id == personal_accounts.c.id
                    )
                    .where(
                        personal_sessions.c.token_digest == token_digest,
                        personal_sessions.c.revoked_at.is_(None),
                        personal_sessions.c.expires_at > func.now(),
                        personal_sessions.c.password_version
                        == personal_accounts.c.password_version,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        account = PersonalAccount(
            username=row["username"],
            password_hash=row["password_hash"],
            must_change_password=row["must_change_password"],
            password_version=row["account_password_version"],
            failed_login_attempts=row["failed_login_attempts"],
            locked_until=row["locked_until"],
        )
        return account, PersonalSession(
            token_digest=row["token_digest"],
            csrf_digest=row["csrf_digest"],
            expires_at=row["expires_at"],
            password_version=row["session_password_version"],
        )

    async def revoke_session(self, token_digest: str) -> None:
        await self._connection.execute(
            update(personal_sessions)
            .where(
                personal_sessions.c.token_digest == token_digest,
                personal_sessions.c.revoked_at.is_(None),
            )
            .values(revoked_at=func.now())
        )

    async def change_password(self, password_hash: str) -> None:
        await self._connection.execute(
            update(personal_accounts)
            .where(personal_accounts.c.id == "personal")
            .values(
                password_hash=password_hash,
                must_change_password=False,
                password_version=personal_accounts.c.password_version + 1,
                updated_at=func.now(),
            )
        )
        await self._connection.execute(delete(personal_sessions))


def _account(row: RowMapping) -> PersonalAccount:
    return PersonalAccount(
        username=row["username"],
        password_hash=row["password_hash"],
        must_change_password=row["must_change_password"],
        password_version=row["password_version"],
        failed_login_attempts=row["failed_login_attempts"],
        locked_until=row["locked_until"],
    )
