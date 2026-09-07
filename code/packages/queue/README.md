# VulnWeaver queue

This package maps versioned `QueueEvent` contracts onto Redis Streams. Publishing uses a
fixed Lua script so a retry with the same immutable event ID returns the original Stream
entry ID instead of appending another entry. The deduplication record has a bounded TTL;
consumers must still treat delivery as at-least-once and deduplicate durable side effects.

`job.requested` is routed to the jobs stream. Status events are routed to the events
stream. Consumer-group read and ACK primitives are provided for T06 workers without
implementing worker leases or execution policy here.
