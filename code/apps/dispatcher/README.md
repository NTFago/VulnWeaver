# VulnWeaver Outbox Dispatcher

The dispatcher locks available PostgreSQL Outbox rows with `FOR UPDATE SKIP LOCKED`,
publishes each immutable event to Redis Streams, and marks it published in the same
database transaction. Retryable Redis failures are recorded with bounded exponential
backoff. Non-retryable conflicts are moved to the Outbox dead-letter state.

The PostgreSQL-to-Redis boundary is intentionally at-least-once: a crash after Redis
accepts an event but before PostgreSQL commits can cause a retry. The queue client uses
the stable event ID to suppress equivalent duplicate Stream entries, while T06 workers
must still make durable side effects idempotent.

Runtime configuration requires `DATABASE_URL` and `REDIS_URL`. The process entry point
also reads optional `DISPATCHER_` settings for batch size, polling and retry delays.
Compose runs `vulnweaver-migrate` as a one-shot dependency before starting the dispatcher.
Both containers run as an unprivileged user with a read-only root filesystem and all Linux
capabilities dropped.
