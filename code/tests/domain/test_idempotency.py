from __future__ import annotations

import pytest
from vulnweaver_domain import IdempotencyKeyError, normalize_idempotency_key


def test_valid_idempotency_key_is_not_rewritten() -> None:
    assert normalize_idempotency_key("task:client-0001") == "task:client-0001"


@pytest.mark.parametrize("value", ["short", " leading-space", "trailing-space ", "含中文字符0000"])
def test_unsafe_idempotency_key_is_rejected(value: str) -> None:
    with pytest.raises(IdempotencyKeyError):
        normalize_idempotency_key(value)
