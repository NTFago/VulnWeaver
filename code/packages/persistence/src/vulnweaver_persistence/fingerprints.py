"""Stable request fingerprints used to distinguish retries from key reuse."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping


def request_fingerprint(payload: Mapping[str, object]) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()
