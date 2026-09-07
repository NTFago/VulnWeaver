# VulnWeaver artifact store

The artifact store owns immutable content bytes. PostgreSQL owns the corresponding
`Artifact` and `ArtifactVersion` metadata. The local backend writes a stream to a staging
file, computes SHA-256 incrementally, and publishes it to a deterministic path with an
exclusive hard link. Existing objects are verified and never overwritten.

Object references have one canonical form:

```text
cas://sha256/<64 lowercase hexadecimal characters>
```

The backend interface does not expose deletion or arbitrary host paths. A future MinIO
backend can implement the same `ArtifactStore` protocol without changing callers.
