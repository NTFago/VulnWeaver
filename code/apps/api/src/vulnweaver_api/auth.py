"""Bounded password authentication and opaque browser sessions."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from vulnweaver_persistence import Database, IdempotencyConflict, PersonalAccount, PersonalSession
from vulnweaver_persistence.fingerprints import request_fingerprint

SESSION_COOKIE = "vulnweaver_session"
CSRF_COOKIE = "vulnweaver_csrf"


class AuthenticationFailed(RuntimeError):
    pass


class PasswordChangeRequired(RuntimeError):
    pass


class PasswordPolicyViolation(ValueError):
    pass


class RegistrationClosed(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LoginResult:
    account: PersonalAccount
    token: str
    csrf_token: str


@dataclass(frozen=True, slots=True)
class AuthenticatedSession:
    account: PersonalAccount
    session: PersonalSession


class PersonalAuthService:
    def __init__(
        self,
        database: Database,
        *,
        session_ttl_seconds: int,
        failure_threshold: int,
        lockout_seconds: int,
        max_password_concurrency: int,
        max_active_sessions: int,
    ) -> None:
        self._database = database
        self._ttl = session_ttl_seconds
        self._failure_threshold = failure_threshold
        self._lockout_seconds = lockout_seconds
        self._max_active_sessions = max_active_sessions
        self._password_slots = asyncio.Semaphore(max_password_concurrency)
        self._hasher = PasswordHasher()
        self._dummy_hash: str | None = None

    async def initialize(self) -> None:
        """Prepare constant-work verification and remove stale session rows."""

        self._dummy_hash = await self._hash(secrets.token_urlsafe(32))
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.purge_sessions()

    async def is_initialized(self) -> bool:
        async with self._database.transaction() as repositories:
            return await repositories.personal_auth.account() is not None

    async def register(self, username: str, password: str) -> LoginResult:
        """Atomically create the installation owner and its first browser session."""

        _validate_username(username)
        _validate_new_password(password)
        password_hash = await self._hash(password)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session = PersonalSession(
            token_digest=_digest(token),
            csrf_digest=_digest(csrf_token),
            expires_at=datetime.now(UTC) + timedelta(seconds=self._ttl),
            password_version=1,
        )
        async with self._database.transaction() as repositories:
            created = await repositories.personal_auth.bootstrap(
                username=username,
                password_hash=password_hash,
                must_change_password=False,
            )
            if not created:
                raise RegistrationClosed("registration is closed for this installation")
            established = await repositories.personal_auth.establish_session(
                session,
                expected_password_version=1,
                max_active_sessions=self._max_active_sessions,
            )
            if not established:
                raise RuntimeError("failed to establish initial session")
        account = PersonalAccount(username, password_hash, False, 1, 0, None)
        return LoginResult(account, token, csrf_token)

    async def login(self, username: str, password: str) -> LoginResult:
        async with self._database.transaction() as repositories:
            account = await repositories.personal_auth.account_by_username(username)
        now = datetime.now(UTC)
        locked = (
            account is not None
            and account.locked_until is not None
            and account.locked_until > now
        )
        candidate_hash = (
            account.password_hash
            if account is not None and not locked
            else self._required_dummy_hash()
        )
        verified = await self._verify(candidate_hash, password)
        if account is None or locked or not verified:
            async with self._database.transaction() as repositories:
                await repositories.personal_auth.record_login_failure(
                    username,
                    threshold=self._failure_threshold,
                    lockout_seconds=self._lockout_seconds,
                )
            raise AuthenticationFailed("invalid username or password")

        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session = PersonalSession(
            token_digest=_digest(token),
            csrf_digest=_digest(csrf_token),
            expires_at=datetime.now(UTC) + timedelta(seconds=self._ttl),
            password_version=account.password_version,
        )
        async with self._database.transaction() as repositories:
            established = await repositories.personal_auth.establish_session(
                session,
                expected_password_version=account.password_version,
                max_active_sessions=self._max_active_sessions,
            )
        if not established:
            raise AuthenticationFailed("credentials changed; sign in again")
        return LoginResult(account, token, csrf_token)

    async def authenticate(
        self, token: str | None, *, allow_password_change: bool = False
    ) -> AuthenticatedSession:
        if not token:
            raise AuthenticationFailed("authentication required")
        async with self._database.transaction() as repositories:
            resolved = await repositories.personal_auth.resolve_session(_digest(token))
        if resolved is None:
            raise AuthenticationFailed("session is invalid or expired")
        account, session = resolved
        if account.must_change_password and not allow_password_change:
            raise PasswordChangeRequired("password must be changed before using the API")
        return AuthenticatedSession(account, session)

    async def authenticate_write(
        self,
        token: str | None,
        csrf_token: str | None,
        *,
        allow_password_change: bool = False,
    ) -> AuthenticatedSession:
        authenticated = await self.authenticate(
            token, allow_password_change=allow_password_change
        )
        if not csrf_token or not hmac.compare_digest(
            authenticated.session.csrf_digest, _digest(csrf_token)
        ):
            raise AuthenticationFailed("CSRF token is invalid")
        return authenticated

    async def logout(self, token: str | None) -> None:
        """Delete a session if present; repeated logout remains successful."""

        if not token:
            return
        async with self._database.transaction() as repositories:
            await repositories.personal_auth.revoke_session(_digest(token))

    async def change_password(
        self,
        token: str | None,
        csrf_token: str | None,
        current: str,
        new: str,
        *,
        idempotency_key: str,
    ) -> bool:
        """Atomically change the password and record a replay-safe HTTP mutation."""

        _validate_new_password(new)
        if not token or not csrf_token:
            raise AuthenticationFailed("authentication and CSRF token are required")
        digest = _digest(token)
        fingerprint = request_fingerprint(
            {"current_password": current, "new_password": new}
        )
        request_scope = f"auth:password:{digest}"
        async with self._database.transaction() as repositories:
            # Serialize all password changes for this session, even when callers
            # accidentally use different idempotency keys.
            await repositories.api_requests.lock(
                scope="auth:password:mutation", key=digest
            )
            prior = await repositories.api_requests.get(
                scope=request_scope, key=idempotency_key
            )
            if prior is not None:
                if prior.request_fingerprint != fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key was already used for a different password change"
                    )
                return False
            resolved = await repositories.personal_auth.resolve_session(digest)
            if resolved is None:
                raise AuthenticationFailed("session is invalid or expired")
            account, session = resolved
            if not hmac.compare_digest(session.csrf_digest, _digest(csrf_token)):
                raise AuthenticationFailed("CSRF token is invalid")
            if not await self._verify(account.password_hash, current):
                raise AuthenticationFailed("current password is invalid")
            password_hash = await self._hash(new)
            changed = await repositories.personal_auth.change_password(
                password_hash,
                token_digest=digest,
                expected_password_version=account.password_version,
            )
            if not changed:
                raise AuthenticationFailed("credentials changed; sign in again")
            await repositories.api_requests.add(
                scope=request_scope,
                key=idempotency_key,
                fingerprint=fingerprint,
                resource_type="personal_account",
                resource_id="personal",
                response_status=204,
            )
        return True

    async def _hash(self, password: str) -> str:
        async with self._password_slots:
            return await asyncio.to_thread(self._hasher.hash, password)

    async def _verify(self, password_hash: str, password: str) -> bool:
        async with self._password_slots:
            try:
                return await asyncio.to_thread(self._hasher.verify, password_hash, password)
            except (InvalidHashError, VerifyMismatchError):
                return False

    def _required_dummy_hash(self) -> str:
        if self._dummy_hash is None:
            raise RuntimeError("authentication service is not initialized")
        return self._dummy_hash


def token_digest(token: str) -> str:
    return _digest(token)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_new_password(password: str) -> None:
    if len(password) < 12 or len(password) > 1024:
        raise PasswordPolicyViolation("password must contain 12-1024 characters")


def _validate_username(username: str) -> None:
    if not username.strip() or username != username.strip() or len(username) > 128:
        raise PasswordPolicyViolation("username must contain 1-128 non-padding characters")
