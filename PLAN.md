# SuperScalar CLN Plugin — Development Plan

## Current State (2026-04-07)

### What Exists

**Plugin** (`superscalar-cln/superscalar.c`, 2988 lines) — a CLN C plugin that implements the SuperScalar channel factory protocol over bLIP-56.

**Supporting files:**
- `factory_state.h/.c` — factory instance structs, query/update functions (12 functions, all implemented)
- `nonce_exchange.h/.c` — MuSig2 nonce bundle serialize/deserialize (2 functions, working)
- `ceremony.h` — submessage IDs (15 defined) and ceremony state enum (9 states)
- `persist.h/.c` — binary serialization for CLN datastore (9 functions, implemented but never called)

**CLN fork** (`cln-blip56`, 18 commits on `blip-56` branch):
- Feature bit 271, wire type 32800, TLV 65600 in `open_channel`
- channeld: STFU quiescence → `factory_change_init` → commitment re-signing via HSMD
- `factory-change` RPC wired through lightningd to channeld
- Splice inflight reuse for factory state tracking

**Library** (`SuperScalar` v0.1.8+) — DW tree construction, MuSig2 signing, factory state management.

---

### Plugin Components — Verified Status

#### RPCs (7 registered)

| RPC | Params | Status | Notes |
|-----|--------|--------|-------|
| `factory-create` | `funding_sats`, `clients[]` | **Working** | Builds DW tree, generates nonces, sends FACTORY_PROPOSE |
| `factory-list` | none | **Working** | Full state dump: instance_id, lifecycle, ceremony, channels[] |
| `factory-rotate` | `instance_id` | **Working** | Advances DW epoch, rebuilds nodes, sends ROTATE_PROPOSE |
| `factory-close` | `instance_id` | **Working** | Inits cooperative close ceremony, sends CLOSE_PROPOSE |
| `factory-force-close` | `instance_id` | **Partial** | Extracts signed txs, closes LN channels, but does NOT broadcast txs |
| `factory-check-breach` | `instance_id`, `txid`, `vout`, `amount_sats`, `epoch` | **Partial** | Builds penalty tx, returns hex, but does NOT broadcast |
| `factory-open-channels` | `instance_id` | **Working** | Calls fundchannel_start+complete per client, maps channels |

#### Hooks (4 registered)

| Hook | Status | Notes |
|------|--------|-------|
| `custommsg` | **Working** | Receives type 32800, dispatches bLIP-56 + SuperScalar submessages |
| `openchannel` | **Working** | Extracts `channel_in_factory` TLV (65600), maps channel to factory |
| `block_added` | **Partial** | Tracks blockheight, checks expiry warnings; breach scanning NOT implemented |
| `connect` | **Working** | Sends `supported_factory_protocols` (submsg 2) |

#### SuperScalar Submessage Handlers (15 defined, all have case statements)

| Submsg | Name | LSP Side | Client Side |
|--------|------|----------|-------------|
| 0x0100 | FACTORY_PROPOSE | Sends (from RPC) | **Full** — builds tree, generates nonces, finalizes, creates psigs, sends NONCE_BUNDLE + PSIG_BUNDLE |
| 0x0101 | NONCE_BUNDLE | **Full** — sets client nonces, finalizes when all collected | Sends (from 0x0100 handler) |
| 0x0102 | ALL_NONCES | Sends (TODO — not yet) | **Stubbed** — sets ceremony state only, no nonce parsing |
| 0x0103 | PSIG_BUNDLE | **Full** — sets client psigs, creates own psigs, completes factory, sends FACTORY_READY | Sends (from 0x0100 handler) |
| 0x0104 | FACTORY_READY | Sends | **Full** — marks ceremony complete |
| 0x0108 | ROTATE_PROPOSE | Sends (from RPC) | **Full** — processes new epoch nonces, sends ROTATE_NONCE + ROTATE_PSIG |
| 0x0109 | ROTATE_NONCE | **Full** — sets rotation nonces, finalizes | Sends (from 0x0108 handler) |
| 0x010A | ROTATE_PSIG | **Full** — sets psigs, completes, sends REVOKE + ROTATE_COMPLETE, triggers factory-change | Sends (from 0x0108 handler) |
| 0x010B | ROTATE_COMPLETE | Sends | **Full** — marks rotation complete |
| 0x010C | REVOKE | Sends | **Full** — stores revocation secret for breach detection |
| 0x0110 | CLOSE_PROPOSE | Sends (from RPC) | **Full** — builds close tx, sends CLOSE_NONCE + CLOSE_PSIG |
| 0x0111 | CLOSE_NONCE | **Full** — sets close nonces, finalizes node 0 | Sends (from 0x0110 handler) |
| 0x0112 | CLOSE_ALL_NONCES | Not sent | **Log only** — needed for N>2 close |
| 0x0113 | CLOSE_PSIG | **Full** — sets psigs, completes close, sends CLOSE_DONE, closes LN channels | Sends (from 0x0110 handler) |
| 0x0114 | CLOSE_DONE | Sends | **Full** — marks factory expired, closes LN channels |

#### bLIP-56 Base Protocol Submessage Handlers

| Submsg | Name | Status | Notes |
|--------|------|--------|-------|
| 2 | supported_factory_protocols | **Full** | Sends on connect, parses on receive |
| 4 | factory_piggyback | **Full** | Unwraps TLV, dispatches to SuperScalar handler |
| 6 | factory_change_init | **Stubbed** | Auto-acks with same TLVs, no validation |
| 8 | factory_change_ack | **Log only** | |
| 10 | factory_change_funding | **Log only** | |
| 12 | factory_change_continue | **Log only** | |
| 14 | factory_change_locked | **Log only** | |

**Note on factory_change (submsg 6-14):** These messages are part of the bLIP-56 base protocol for channel state changes. In our architecture, `factory-change` goes through channeld (wire messages 7230-7236), not through the plugin. The plugin handlers exist for logging/debugging when custommsg relays these, but the actual state machine lives in channeld. The stubbed handlers are acceptable because channeld handles the real flow.

#### Channel Lifecycle Wiring

| Event | Action | Status |
|-------|--------|--------|
| Ceremony complete (PSIG_BUNDLE → FACTORY_READY) | Call `factory-open-channels` RPC (manual) | **Working** |
| Rotation complete (ROTATE_PSIG → ROTATE_COMPLETE) | Call `factory-change` on each open channel | **Working** |
| Cooperative close (CLOSE_PSIG → CLOSE_DONE) | Call `close` on each open channel (both sides) | **Working** |
| Force close (RPC) | Call `close` with `unilateraltimeout=1` on each channel | **Working** |

#### Persistence

`persist.c` has 9 functions for binary serialization to CLN's `datastore` API:
- `ss_persist_serialize_meta()` / `deserialize_meta()`
- `ss_persist_serialize_channels()` / `deserialize_channels()`
- `ss_persist_serialize_breach()` / `deserialize_breach()`
- Key builders: `ss_persist_key_meta()`, `_channels()`, `_breach()`

**Status: Never called.** No `datastore` RPC invocations exist in `superscalar.c`. Factory state is lost on plugin restart.

---

### How the 2-Party Ceremony Actually Works

For the LSP + 1 client case (current demo), the ceremony shortcuts the ALL_NONCES round:

```
LSP                                     Client
 |                                        |
 |-- factory-create RPC ----------------->|
 |   (builds tree, generates nonces)      |
 |                                        |
 |-- FACTORY_PROPOSE (nonce_bundle) ----->|
 |                                        | builds tree
 |                                        | sets LSP nonces
 |                                        | generates own nonces
 |                                        | finalizes (has all nonces)
 |                                        | creates partial sigs
 |<--- NONCE_BUNDLE --------------------- |
 |<--- PSIG_BUNDLE ---------------------- | (both sent immediately)
 |                                        |
 | sets client nonces                     |
 | finalizes                              |
 | sets client psigs + creates own        |
 | factory_sessions_complete()            |
 |                                        |
 |-- FACTORY_READY ---------------------->|
 |                                        | ceremony = COMPLETE
 |                                        |
 |-- factory-open-channels RPC           |
 |   fundchannel_start ----------------->|
 |   fundchannel_complete <-- PSBT       |
 |                                        | openchannel hook maps channel
 |                                        |
 | channel appears in listpeerchannels   |
```

The client sends NONCE_BUNDLE and PSIG_BUNDLE back-to-back because with only 2 signers, both sets of nonces are known immediately (LSP's came in FACTORY_PROPOSE, client generates its own). No aggregation round needed.

For N>2 clients, the ALL_NONCES round is required: LSP collects all clients' NONCE_BUNDLEs, aggregates, sends ALL_NONCES to each client, then each client creates partial sigs. This path is NOT implemented.

---

## Remaining Work

### Tier 1 — Build & Test (Get it Running)

**Goal:** Prove the 2-party lifecycle works end-to-end on VPS.

**T1.1: VPS Build**
- Pull superscalar-cln on VPS
- Pull cln-blip56 on VPS
- Patch Makefile: add `-I/root/SuperScalar/include` to CFLAGS, add plugin entries to plugins/Makefile
- Build CLN fork (make -j4)
- Verify plugin loads: `lightning-cli plugin list` shows superscalar

**T1.2: 2-Node Test — Factory Creation**
- Start 2 CLN nodes (LSP + client), connect them
- On LSP: `lightning-cli factory-create 1000000 '["<client_node_id>"]'`
- Verify: ceremony completes (FACTORY_PROPOSE → NONCE_BUNDLE → PSIG_BUNDLE → FACTORY_READY)
- Verify: `factory-list` shows lifecycle=init→complete on both sides

**T1.3: Channel Opening**
- On LSP: `lightning-cli factory-open-channels <instance_id>`
- Verify: `listpeerchannels` shows a channel on both sides
- Verify: `listpeerchannels` shows `channel_in_factory` TLV fields

**T1.4: Rotation**
- On LSP: `lightning-cli factory-rotate <instance_id>`
- Verify: rotation ceremony completes (ROTATE_PROPOSE → ROTATE_NONCE → ROTATE_PSIG �� REVOKE → ROTATE_COMPLETE)
- Verify: `factory-change` called on open channel
- Verify: channel's funding outpoint updated (or at least no crash)

**T1.5: Cooperative Close**
- On LSP: `lightning-cli factory-close <instance_id>`
- Verify: close ceremony completes (CLOSE_PROPOSE → CLOSE_NONCE → CLOSE_PSIG → CLOSE_DONE)
- Verify: channels close on both sides

**T1.6: Force Close**
- Create a new factory, open channels
- On LSP: `lightning-cli factory-force-close <instance_id>`
- Verify: returns signed transaction hex
- Verify: channels close

**Expected issues:** Likely to hit compilation errors (CLN API changes, missing includes), message framing bugs, and timing issues. Each will need investigation and fixing.

---

### Tier 2 — Complete the Demo (Make it Solid)

**Goal:** Fix bugs found in Tier 1, fill remaining gaps for a reliable 2-party demo.

**T2.1: Broadcast Transactions in Force-Close**
In `json_factory_force_close`, after extracting signed txs, call `sendrawtransaction` for each:
```c
struct out_req *req = jsonrpc_request_start(cmd,
    "sendrawtransaction", rpc_done, rpc_err, fi);
json_add_string(req->js, "tx", tx_hex);
send_outreq(req);
```
File: `superscalar.c`, in the force-close loop (~10 lines)

**T2.2: Broadcast Penalty Tx in Check-Breach**
Same pattern — call `sendrawtransaction` with the penalty tx hex.
File: `superscalar.c`, end of `json_factory_check_breach` (~5 lines)

**T2.3: Wire Persistence**
Add `datastore` RPC calls at key lifecycle points:
- After `CEREMONY_COMPLETE`: save factory meta + channels via `datastore` RPC
- After rotation: update epoch + breach data
- After close: mark factory expired
- On plugin init: load factories from `datastore`

This uses the already-implemented `persist.c` serialization functions. Need ~80 lines of RPC glue in `superscalar.c`:
```c
/* Save factory state to CLN datastore */
static void persist_factory(struct command *cmd, factory_instance_t *fi) {
    uint8_t buf[4096];
    size_t len = ss_persist_serialize_meta(fi, buf, sizeof(buf));
    char *key = ss_persist_key_meta(fi->instance_id);
    struct out_req *req = jsonrpc_request_start(cmd,
        "datastore", rpc_done, rpc_err, fi);
    json_add_string(req->js, "key", key);
    json_add_hex_talarr(req->js, "hex", buf, len);
    json_add_string(req->js, "mode", "create-or-replace");
    send_outreq(req);
}
```
And restore on init:
```c
/* In init(), query datastore for existing factories */
```

**T2.4: Parameterize Hardcoded Values**
Replace hardcoded values with factory creation params:

| Hardcoded | Current | Should Be |
|-----------|---------|-----------|
| Channel funding | 500000 sat | `funding_sats / n_clients` |
| Factory total | 1000000 sat | `funding_sats` from RPC param |
| DW step_blocks | 144 | Configurable (default 144) |
| DW states_per_layer | 16 | Configurable (default 16) |

Store these in `factory_instance_t` and reference them in channel opening and close.

**T2.5: Active Breach Monitoring**
In `handle_block_added`, for each active factory with breach data:
- Extract txids from the block (via `getblock` or the notification payload)
- Compare against stored old-epoch txids
- If match found, build and broadcast penalty tx

This is ~40 lines in the block_added handler.

---

### Tier 3 — Multi-Client Support (Make it Real)

**Goal:** Support factories with 2+ clients (the actual SuperScalar design).

**T3.1: LSP Sends ALL_NONCES**
After all clients' NONCE_BUNDLEs are collected and sessions are finalized, serialize the aggregated nonces and send ALL_NONCES to each client:
```c
/* After factory_sessions_finalize succeeds */
for (size_t ci = 0; ci < fi->n_clients; ci++) {
    /* Serialize aggregated nonces for all nodes */
    /* Send ALL_NONCES via send_factory_msg */
}
```
The aggregated nonces come from `factory->nodes[ni].signing_session.aggnonce`. Need a serialization format — can reuse nonce_bundle_t or define a new wire format.

Approximately ~50 lines.

**T3.2: Client Parses ALL_NONCES**
In the `SS_SUBMSG_ALL_NONCES` handler, parse the aggregated nonces, set them on sessions, finalize, create partial sigs, and send PSIG_BUNDLE:
```c
case SS_SUBMSG_ALL_NONCES:
    /* Parse aggregated nonces from payload */
    /* Set on sessions via factory_session_set_aggnonce() or similar */
    /* Finalize sessions */
    /* Create partial sigs (same logic as in FACTORY_PROPOSE handler) */
    /* Send PSIG_BUNDLE */
```
Approximately ~80 lines (similar to the partial sig creation in FACTORY_PROPOSE).

**T3.3: Multi-Client Channel Opening**
Currently `open_factory_channels` opens one channel per client. For multi-client factories, each client's channel maps to a specific DW leaf. The leaf assignment logic needs to match the tree structure.

**T3.4: Multi-Client Close (CLOSE_ALL_NONCES)**
Same pattern as ALL_NONCES but for the close ceremony. LSP aggregates close nonces and sends CLOSE_ALL_NONCES to all clients before they create close partial sigs.

---

### Tier 4 — Production Hardening

**Goal:** Replace demo shortcuts with real cryptographic operations.

**T4.1: Real Key Management**
Replace `derive_demo_seckey()` with actual node key signing via HSMD. The plugin would need to request signatures from the HSMD rather than holding raw private keys. This is a significant architectural change.

**T4.2: Proper PSBT Construction**
Currently `fundchannel_start_ok` builds a PSBT with 0 inputs and 1 output. For production, the PSBT must reference the actual DW leaf parent's outpoint as the funding input. The first `factory-change` after creation should update this, but ideally the initial PSBT is correct.

**T4.3: Reconnection & Ceremony Recovery**
If a peer disconnects mid-ceremony, the current code has no way to resume. Need:
- Ceremony timeout (mark FAILED after N blocks without progress)
- Re-send last message on reconnect
- Handle duplicate messages gracefully

**T4.4: Factory-Change Plugin Integration**
The bLIP-56 factory_change messages (submsg 6-14) flow through channeld, not the plugin. But the plugin should validate them:
- submsg 6 (factory_change_init): Verify the new funding txid matches our factory's expected new leaf
- submsg 14 (factory_change_locked): Update our stored funding outpoint

Currently these just log. For production, add validation (~30 lines per handler).

**T4.5: Error Recovery**
- If `fundchannel_start` fails: retry or mark factory as failed
- If `factory-change` fails: retry or initiate force-close
- If rotation fails mid-way: revert epoch counter, reset ceremony
- If close ceremony stalls: timeout to force-close

---

## Execution Order

```
Tier 1: Build & Test                    ← NEXT (biggest risk reduction)
  T1.1 → T1.2 → T1.3 → T1.4 → T1.5 → T1.6
  (fix bugs as they surface)

Tier 2: Complete the Demo               ← After Tier 1 works
  T2.1 (broadcast force-close)
  T2.2 (broadcast penalty)
  T2.3 (persistence)
  T2.4 (parameterize)
  T2.5 (breach monitoring)

Tier 3: Multi-Client                    ← When 2-party is solid
  T3.1 → T3.2 (ALL_NONCES round)
  T3.3 (multi-client channel opening)
  T3.4 (multi-client close)

Tier 4: Production                      ← Long-term
  T4.1 (HSMD key management)
  T4.2 (proper PSBTs)
  T4.3 (reconnection)
  T4.4 (factory-change validation)
  T4.5 (error recovery)
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                    CLN Node                          │
│                                                      │
│  ┌──────────────┐    ┌─────────────────────────────┐│
│  │  lightningd   │    │  SuperScalar Plugin          ││
│  │               │    │                              ││
│  │  fund-        │◄──►│  factory-create              ││
│  │  channel_     │    │  factory-open-channels       ││
│  │  start/       │    │  factory-rotate              ││
│  │  complete     │    │  factory-close               ││
│  │               │    │  factory-force-close         ││
│  │  close        │    │  factory-check-breach        ││
│  │               │    │  factory-list                ││
│  │  factory-     │    │                              ││
│  │  change       │    │  ┌────────────────────────┐  ││
│  │  (RPC)        │    │  │  libsuperscalar.a      │  ││
│  │               │    │  │  - DW tree build        │  ││
│  └───────┬───────┘    │  │  - MuSig2 sessions     │  ││
│          │            │  │  - Nonce pools          │  ││
│  ┌───────┴───────┐    │  │  - Factory state        │  ││
│  │   channeld     │    │  └────────────────────────┘  ││
│  │               │    │                              ││
│  │  STFU         │    │  custommsg hook ◄─── wire    ││
│  │  factory_     │    │    → dispatch_blip56_submsg  ││
│  │  change_init  │    │      → submsg 4 (piggyback)  ││
│  │  commitment   │    │        → dispatch_superscalar ││
│  │  re-sign      │    │                              ││
│  │  via HSMD     │    │  openchannel hook            ││
│  └───────────────┘    │    → map channel to factory  ││
│                       └─────────────────────────────┘│
└─────────────────────────────────────────────────────┘

Wire Protocol (between peers):
  type 32800 (factory_message)
    submsg 2: supported_factory_protocols
    submsg 4: factory_piggyback → TLV[0]=protocol_id + TLV[1024]=payload
      payload: SuperScalar submsg (0x0100-0x0114) + data
    submsg 6-14: factory_change_* (handled by channeld)

  open_channel TLV 65600: channel_in_factory
    factory_protocol_id (32 bytes)
    factory_instance_id (32 bytes)
    factory_early_warning_time (u16)
```

---

## File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `superscalar.c` | 2988 | Main plugin: RPCs, hooks, ceremony, dispatch |
| `factory_state.h` | 181 | Structs: factory_instance_t, superscalar_state_t |
| `factory_state.c` | 160 | State query/update functions |
| `ceremony.h` | 69 | Submessage IDs, ceremony state enum |
| `nonce_exchange.h` | 51 | nonce_bundle_t struct |
| `nonce_exchange.c` | 79 | Bundle serialize/deserialize |
| `persist.h` | 44 | Persistence function declarations |
| `persist.c` | 282 | Binary serialization for CLN datastore |

---

## Key Design Decisions

1. **Factory internals stay internal.** The DW tree, MuSig2 sessions, and epoch management are plugin-private. CLN only sees normal LN channels with factory TLV metadata. channeld doesn't know about factories — it just does STFU + re-sign when told.

2. **SuperScalar messages use factory_piggyback (submsg 4).** All 13 SuperScalar protocol message sends are wrapped in bLIP-56's piggyback format with protocol_id = "SuperScalar/v1". This allows other factory protocols to coexist on the same bLIP-56 infrastructure.

3. **Channel opening is a separate RPC.** `factory-open-channels` is called manually after ceremony completion, not automatically. This gives the LSP control over timing and avoids async cmd context issues.

4. **2-party ceremony skips ALL_NONCES round.** With only 2 signers, the client has all nonces after FACTORY_PROPOSE and can immediately finalize + create partial sigs. This is a valid optimization for the common case.

5. **factory-change goes through channeld, not the plugin.** The plugin triggers it via the `factory-change` RPC, but the actual STFU→re-sign→lock flow is handled by channeld's wire protocol. The plugin's submsg 6-14 handlers are informational only.
