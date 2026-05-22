# SuperScalar JSON-RPC Error Codes

The plugin returns numeric error codes in the `code` field of JSON-RPC error responses. Codes are stable: a given code always maps to the same failure category. Codes will be added over time; clients should treat unrecognized codes as "unknown server error" rather than failing.

## Code ranges

- `-32602` (`JSONRPC2_INVALID_PARAMS`) — CLN-defined; returned for param-shape validation failures (missing field, wrong type, etc.). See CLN docs.
- `2200–2299` — SuperScalar plugin-specific. Listed below.
- `-1` (`LIGHTNINGD`) — generic catch-all; returned by call sites not yet migrated. Treat the same as a code in the 2200s with category unknown.

## SuperScalar codes (2200-2299)

| Code | Symbol                          | Meaning                                                                 | Retry? |
|------|---------------------------------|-------------------------------------------------------------------------|--------|
| 2200 | `SS_ERR_INTERNAL`               | Generic internal error; check logs                                       | No     |
| 2210 | `SS_ERR_PEER_RATE_LIMIT`        | Peer exceeded rate limit / concurrent cap / is soft-banned              | After window (60s rate, 300s ban) |
| 2211 | `SS_ERR_PEER_CONCURRENT_LIMIT`  | (Reserved; not yet split from 2210)                                      | After in-flight clears |
| 2212 | `SS_ERR_PEER_SOFT_BANNED`       | (Reserved; not yet split from 2210)                                      | After 300s |
| 2213 | `SS_ERR_PEER_TABLE_FULL`        | (Reserved) per-peer tracking table saturated                             | Rare |
| 2220 | `SS_ERR_SLOT_EXHAUSTED`         | Global browse/join slot pool full (16 slots/RPC type)                    | After in-flight clears |
| 2230 | `SS_ERR_PEER_NOT_CONNECTED`     | (Reserved) target peer not connected via BOLT-8                          | After reconnect |
| 2231 | `SS_ERR_PEER_NOT_BLIP56`        | (Reserved) peer does not advertise pluggable_channel_factories (bit 271) | No     |
| 2240 | `SS_ERR_UNKNOWN_FACTORY`        | (Reserved) instance_id not known to host                                 | No     |
| 2241 | `SS_ERR_FACTORY_QUEUE_FULL`     | (Reserved) host factory join queue full                                  | After kick/decline |
| 2242 | `SS_ERR_DUPLICATE_JOIN`         | Already have an active outgoing join for this factory                    | Cancel existing first |
| 2243 | `SS_ERR_OUTGOING_JOINS_FULL`    | Local outgoing_joins persistence cap reached                             | Cancel/wait |
| 2244 | `SS_ERR_INSTANCE_ID_INVALID`    | instance_id / node_id failed hex-length validation post-parse            | No     |
| 2250 | `SS_ERR_REQUEST_TIMEOUT`        | (Reserved) request timed out waiting for peer response                   | After deadline |

## Migration policy

Sites returning generic `-1` are progressively being migrated. Codes in the **Reserved** state are defined but not yet used at any call site — they have stable numbers reserved so clients can pre-author handlers.

Wallet/dashboard consumers should switch on the numeric `code` first; fall back to message regex only when the code is unfamiliar.

## Audit trail

Companion to error codes, the plugin also emits structured audit log lines (see `ss_audit_log`) for events that justify forensic review. Audit lines parse as JSON: `{"audit":"<event>","key":"value",...}`. Routing those to a separate index alongside the JSON-RPC error stream gives a complete picture of rejected operations.
