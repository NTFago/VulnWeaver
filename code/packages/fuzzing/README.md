# Fuzzing and crash triage

This package contains the safe, deterministic part of the fuzzing pipeline: budgets,
crash manifest normalization, stack-frame hashing, and cluster identity. Actual fuzz
tool execution is intentionally routed through the Sandbox Runner.
