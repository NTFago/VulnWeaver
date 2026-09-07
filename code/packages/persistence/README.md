# VulnWeaver persistence

This package owns the PostgreSQL control-plane schema, immutable Alembic revisions and
transaction-scoped repositories. Callers open one `Database.transaction()` context and
use only the repositories yielded by that context; a Job and its Outbox event therefore
share one commit or rollback boundary.

Apply migrations from `code/` without placing credentials in configuration files:

```shell
alembic -c packages/persistence/alembic.ini upgrade head
```

Service startup should normally call `upgrade_database(DATABASE_URL)` through the
deployment migration job. The URL is injected at runtime and must use
`postgresql+psycopg://`.

The initial revision covers Project, Artifact/ArtifactVersion, Task, Job, Outbox and
TaskEvent. Finding/Evidence and PAIR tables are added by their owning task packages when
those contracts acquire persistence behavior.

T06 adds transaction-scoped Job lease primitives. `claim_lease()` locks the Job row and
uses PostgreSQL server time to grant the first attempt or take over an expired lease;
`renew_lease()` and `release_lease()` require the exact owner. The database lease is the
execution authority even when Redis redelivers a pending message.

Terminal Worker results are stored in immutable `job_results` rows keyed by Job ID.
`complete()` inserts that result and updates the Job terminal state in one transaction;
an identical replay is idempotent even after the lease has been released, while a
different result is rejected. `fail_exhausted()` is restricted to Jobs that have already
consumed their configured attempts and have no active lease.
