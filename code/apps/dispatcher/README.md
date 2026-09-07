# VulnWeaver Outbox Dispatcher

The dispatcher handles one PostgreSQL Outbox row per transaction with
`FOR UPDATE SKIP LOCKED`, publishes the immutable event to Redis Streams, and records
the outcome before committing. This prevents one slow Redis call from locking a whole
batch. Retryable Redis failures use database time and bounded exponential backoff;
they continue retrying because silently abandoning a fact event would lose delivery.
Non-retryable conflicts are moved to the Outbox dead-letter state.

The PostgreSQL-to-Redis boundary is intentionally at-least-once: a crash after Redis
accepts an event but before PostgreSQL commits can cause a retry. The queue client uses
the stable event ID to suppress equivalent duplicate Stream entries, while T06 workers
must still make durable side effects idempotent.

Runtime configuration requires `DATABASE_URL` and `REDIS_URL`. The process entry point
also reads optional `DISPATCHER_` settings for batch size, polling and retry delays.
Compose runs `vulnweaver-migrate` as a one-shot dependency before starting the dispatcher.
Both containers run as an unprivileged user with a read-only root filesystem and all Linux
capabilities dropped.
