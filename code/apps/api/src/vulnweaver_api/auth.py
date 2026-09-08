"""Cookie sessions for one local personal account, without roles or memberships."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from vulnweaver_persistence import Database, PersonalAccount, PersonalSession

SESSION_COOKIE = "vulnweaver_session"


class AuthenticationFailed(RuntimeError):
    pass


class PasswordChangeRequired(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LoginResult:
    account: PersonalAccount
    token: str
    csrf_token: str


class PersonalAuthService:
    def __init__(self, database: Database, *, session_ttl_seconds: int) -> None:
        self._database = database
        self._ttl = session_ttl_seconds
        self._hasher = PasswordHasher()

    async def bootstrap(
        self, username: str, password: str, *, must_change_password: bool = True
    ) -> bool:
        _validate_new_password(password)
        password_hash = await asyncio.to_thread(self._hasher.hash, password)
        async with self._database.transaction() as repositories:
            return await repositories.personal_auth.bootstrap(
                username=username,
                password_hash=password_hash,
                must_change_password=must_change_password,
            )

    async def login(self, username: str, password: str) -> LoginResult:
        async with self._database.transaction() as repositories:
            account = await repositories.personal_auth.account_by_username(username)
        now = datetime.now(UTC)
        if account is not None and account.locked_until is not None and account.locked_until > now:
            raise AuthenticationFailed("invalid username or password")
        if account is None or not await self._verify(account.password_hash, password):
            async with self._database.transaction() as repositories:
                await repositories.personal_auth.record_login_failure(
                    username,
                    threshold=5,
                    locked_until=now + timedelta(minutes=5),
                )
            raise AuthenticationFailed("invalid username or password")
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.record_login_success()
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session = PersonalSession(
            token_digest=_digest(token),
            csrf_digest=_digest(csrf_token),
            expires_at=datetime.now(UTC) + timedelta(seconds=self._ttl),
            password_version=account.password_version,
        )
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.add_session(session)
        return LoginResult(account, token, csrf_token)

    async def authenticate(
        self, token: str | None, *, allow_password_change: bool = False
    ) -> PersonalAccount:
        if not token:
            raise AuthenticationFailed("authentication required")
        async with self._database.transaction() as repositories:
            resolved = await repositories.personal_auth.resolve_session(_digest(token))
        if resolved is None:
            raise AuthenticationFailed("session is invalid or expired")
        account, _ = resolved
        if account.must_change_password and not allow_password_change:
            raise PasswordChangeRequired("password must be changed before using the API")
        return account

    async def verify_csrf(self, token: str, csrf_token: str | None) -> None:
        if not csrf_token:
            raise AuthenticationFailed("CSRF token is required")
        async with self._database.transaction() as repositories:
            resolved = await repositories.personal_auth.resolve_session(_digest(token))
        if resolved is None or not hmac.compare_digest(
            resolved[1].csrf_digest, _digest(csrf_token)
        ):
            raise AuthenticationFailed("CSRF token is invalid")

    async def logout(self, token: str) -> None:
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.revoke_session(_digest(token))

    async def change_password(self, token: str, current: str, new: str) -> None:
        _validate_new_password(new)
        account = await self.authenticate(token, allow_password_change=True)
        if not await self._verify(account.password_hash, current):
            raise AuthenticationFailed("current password is invalid")
        password_hash = await asyncio.to_thread(self._hasher.hash, new)
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.change_password(password_hash)

    async def _verify(self, password_hash: str, password: str) -> bool:
        try:
            return await asyncio.to_thread(self._hasher.verify, password_hash, password)
        except (InvalidHashError, VerifyMismatchError):
            return False


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_new_password(password: str) -> None:
    if len(password) < 12 or len(password) > 1024:
        raise ValueError("password must contain 12-1024 characters")
