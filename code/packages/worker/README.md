# VulnWeaver Worker SDK

This package owns the reliable lifecycle shared by concrete workers. It consumes
`job.requested` entries through a Redis consumer group, takes an authoritative
PostgreSQL lease, renews that lease while the executor runs, stores one immutable
terminal `WorkerResult`, and only then acknowledges or dead-letters the entry.

Concrete analysis workers provide a `JobExecutor`; they do not implement their own
queue acknowledgement, lease, retry, or shutdown logic. The SDK does not execute
commands, mount the Docker socket, or replace the Sandbox Runner boundary.

An active lease returned as `already_owned` is never executed again, even if Redis PEL
idle ownership moved away and back to the same consumer. A failed attempt is retried only
when its structured failure is marked retryable, its kind is explicitly allowed by the
Job retry policy, and another attempt remains; the failure is durably appended before the
lease is released.
