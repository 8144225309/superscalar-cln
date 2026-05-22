# SuperScalar plugin — RPC catalog

Auto-extracted from `superscalar.c` commands[] + handler doc-blocks.
Re-run `scripts/gen_rpc_catalog.py` to refresh.

Total: 65 SuperScalar RPCs.

**Layer 1 protocol** (BOLT-8 custommsg, wire types `0x0140`-`0x014C`)
is not in this catalog — see `CONFORMANCE.md` and `ceremony_wire.h`.
All RPCs below are **local** (CLN lightning-rpc Unix socket → plugin).

## `factory-*` — protocol & lifecycle RPCs

| RPC | Params | Description |
|---|---|---|
| `factory-abort-stuck` | instance_id (req), force | factory-abort-stuck — operator-facing RPC. |
| `factory-approve-proposal` | (none) |  |
| `factory-browse-host` | node_id (req), since_block, address |  |
| `factory-buy-liquidity` | instance_id (req), client_idx (req), amount_sats (req) | Collect cooperative (departed) client node IDs */ |
| `factory-cancel-join` | request_id (req) | ----- factory-cancel-join ------------------------------------------------ |
| `factory-check-breach` | instance_id (req), txid (req), vout (req), amount_sats (req), epoch (req) | Ladder lifecycle: advance block, evict expired factories, |
| `factory-close` | instance_id (req) | factory-close RPC — LSP initiates cooperative close. |
| `factory-close-departed` | instance_id (req), client_idx (req) | Store signed TX data for cascade rebroadcast on each block. |
| `factory-confirm-closed` | instance_id (req) | Phase 1 trustless-watcher: explicit operator reap of a factory the |
| `factory-create` | funding_sats (req), clients (req), allocations, arity_mode, feerate_perkw, defer_signing |  |
| `factory-force-close` | instance_id (req) | Step 5: send PROPOSE to the affected client */ |
| `factory-funding-precheck` | funding_sats (req), fee_estimate_sats, strict |  |
| `factory-get-cached-policy` | lsp_peer_id, instance_id |  |
| `factory-incoming-joins` | instance_id | Build wire payload: req_id(8) + instance_id(32) + tlv_len(2) = 42 */ |
| `factory-initiate-exit` | instance_id (req), client_id (req) | Stash the LSP's own pubnonce in slot order. |
| `factory-join-request` | lsp_node_id (req), instance_id (req), contribution_sats (req), address |  |
| `factory-kick-joiner` | instance_id (req), client_node_id (req), reason | ----- factory-kick-joiner ------------------------------------------------ |
| `factory-ladder-status` | (none) | factory-initiate-exit RPC — LSP triggers key turnover for a client. |
| `factory-list` | (none) | Revert lifecycle on failure so re-trigger is possible. |
| `factory-metrics` | (none) |  |
| `factory-migrate` | instance_id (req) | Initialize ladder (multi-factory lifecycle manager). |
| `factory-migrate-complete` | instance_id (req) | Step 1: Send TURNOVER_REQUEST to all connected, non-departed clients */ |
| `factory-open-channels` | instance_id (req) | Re-send ALL_NONCES so client can respond with |
| `factory-ps-advance` | instance_id (req), leaf_side (req) | Cache the ROTATE_PROPOSE payload for reconnect recovery. |
| `factory-refuse-proposal` | (none) |  |
| `factory-reorg-check` | instance_id (req) | factory-reorg-check — operator-facing RPC to re-validate confirmed |
| `factory-review-proposal` | instance_id (req), lsp_peer_id | B2: factory-review-proposal RPC — read-only view of the most recent |
| `factory-rotate` | instance_id (req) | Append nonce bundle (heap alloc: 79KB struct) */ |
| `factory-scan-external-close` | instance_id (req) | Capture lifecycle for the log message before we free fi. |
| `factory-source-check` | instance_id (req) | dev-factory-mark-cpfp-parent-confirmed — flip parent_confirmed_block |
| `factory-trigger-ceremony` | factory_instance_id_hex (req), force, deadline_block | PR 3b: set funding_amount_sats before the kickoff helper. |

## `wallet-*` — local SQLite query/write RPCs (used by the wallet UI)

| RPC | Params | Description |
|---|---|---|
| `wallet-approve-join-queued` |  |  |
| `wallet-count-join-queue-by-status` |  |  |
| `wallet-get-factory` |  |  |
| `wallet-get-factory-policy-snapshot` |  |  |
| `wallet-get-iid-counter` |  |  |
| `wallet-get-latest-event-id` |  |  |
| `wallet-get-operator-pref` |  |  |
| `wallet-get-peer-note` |  |  |
| `wallet-get-peer-reputation` |  |  |
| `wallet-get-setting` |  |  |
| `wallet-get-signing-pref` |  |  |
| `wallet-increment-iid-counter` |  |  |
| `wallet-list-events-since` |  |  |
| `wallet-list-factories-by-role` |  |  |
| `wallet-list-join-queue-by-status` |  |  |
| `wallet-list-known-peers` |  |  |
| `wallet-list-outgoing-joins-by-status` |  |  |
| `wallet-refuse-join-queued` |  |  |
| `wallet-save-factory-policy-snapshot` |  |  |
| `wallet-set-iid-counter` |  |  |
| `wallet-set-operator-pref` |  |  |
| `wallet-set-peer-note` |  |  |
| `wallet-set-peer-reputation` |  |  |
| `wallet-set-setting` |  |  |
| `wallet-set-signing-pref` |  |  |
| `wallet-status` |  |  |
| `wallet-upsert-factory` |  |  |
| `wallet-upsert-join-queue-entry` |  |  |
| `wallet-upsert-outgoing-join` |  |  |

## `client-*` — client-role helpers

| RPC | Params | Description |
|---|---|---|
| `client-dismiss-sign-queue-event` | instance_id (req) |  |
| `client-list-held-proposals` | (none) |  |
| `client-list-recent-sign-queue-events` | (none) |  |
| `client-signing-prefs-get` | (none) |  |
| `client-signing-prefs-set` | prefs (req) |  |

## CLI defaults vs wallet defaults (task #41 scan)

Spot-check of where the wallet quietly defaults a param vs what the CLI requires explicit:

| RPC | Wallet behavior | CLI behavior | Divergence? |
|---|---|---|---|
| `factory-create` | `feerate_perkw=1000` sent if user leaves it blank in modal | CLI rejects without `feerate_perkw` | Convenience only |
| `factory-trigger-ceremony` | `force=false` unless toggled | Same default | No |
| `factory-rotate` | Just `instance_id` | Same | No |
| `factory-browse-host` | Wallet passes `address` hint from local peer record if known | CLI requires manual `address=` | Convenience only |
| `factory-join-request` | Same as browse-host | CLI requires manual `address=` | Convenience only |
| `wallet-set-operator-pref` | Wallet wraps value in JSON quotes | CLI accepts bare or quoted | Both equivalent |

**No protocol-level divergence found.** Every wallet default is local convenience;
nothing changes wire behavior between LSP and client.

## Wallet usage

RPCs the wallet calls via `FactoriesService.clnCall(...)`:

- `factory-list`
- `factory-create`
- `factory-rotate`
- `factory-close`
- `factory-force-close`
- `factory-trigger-ceremony`
- `factory-open-channels`
- `factory-browse-host`
- `factory-join-request`
- `factory-cancel-join`
- `factory-approve-proposal`
- `factory-refuse-proposal`
- `factory-review-proposal`
- `factory-check-breach`
- `factory-get-cached-policy`
- `client-list-held-proposals`
- `client-list-recent-sign-queue-events`
- `client-dismiss-sign-queue-event`
- `client-signing-prefs-get`
- `client-signing-prefs-set`
- `wallet-list-known-peers`
- `wallet-set-peer-note`
- `wallet-get-peer-note`
- `wallet-set-peer-reputation`
- `wallet-get-peer-reputation`
- `wallet-list-join-queue-by-status`
- `wallet-count-join-queue-by-status`
- `wallet-approve-join-queued`
- `wallet-refuse-join-queued`
- `wallet-set-operator-pref`
- `wallet-get-operator-pref`
- `wallet-list-events-since`
- `wallet-get-latest-event-id`

(33 of the 65 total RPCs are surfaced in the wallet UI.)

