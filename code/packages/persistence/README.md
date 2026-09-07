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
