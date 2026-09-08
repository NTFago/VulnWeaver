"""Browser cookie policy for personal-account sessions."""

from fastapi import Response

from vulnweaver_api.auth import CSRF_COOKIE, SESSION_COOKIE


def set_session_cookies(
    response: Response,
    *,
    session_token: str,
    csrf_token: str,
    secure: bool,
    max_age: int,
) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    # The browser echoes this token in X-CSRF-Token. The server compares its
    # digest with the value bound to the opaque session.
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        path="/",
        secure=secure,
        httponly=False,
        samesite="strict",
    )


def delete_session_cookies(response: Response, *, secure: bool) -> None:
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        CSRF_COOKIE,
        path="/",
        secure=secure,
        httponly=False,
        samesite="strict",
    )
