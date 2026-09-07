"""Shared idempotency-key normalization rules."""

from __future__ import annotations

import re

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class IdempotencyKeyError(ValueError):
    """Raised when an external idempotency key is unsafe or ambiguous."""


def normalize_idempotency_key(value: str) -> str:
    """Validate without silently trimming or rewriting caller identity."""

    if not _IDEMPOTENCY_KEY.fullmatch(value):
        raise IdempotencyKeyError(
            "idempotency key must be 8-128 ASCII letters, digits, '.', '_', ':' or '-'"
        )
    return value
