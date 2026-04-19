# superscalar-cln

SuperScalar channel factory plugin for [Core Lightning](https://github.com/ElementsProject/lightning). Implements [bLIP-56](https://github.com/lightning/blips/pull/56) (pluggable channel factories) using Decker-Wattenhofer state trees with MuSig2 signing.

This plugin enables a Core Lightning node to participate in [SuperScalar](https://github.com/8144225309/SuperScalar) channel factories — shared UTXOs that give multiple users non-custodial Lightning channel access in a single on-chain transaction. For a detailed explanation of the protocol, visit [superscalar.win](https://superscalar.win).

## Requirements

- [Core Lightning (bLIP-56 fork)](https://github.com/8144225309/lightning/tree/blip-56) — the `blip-56` branch with TLV 65600, feature bit 270/271, STFU-gated factory-change, and batch commitment_signed support
- Bitcoin Core 28+
- [SuperScalar](https://github.com/8144225309/SuperScalar) built from source (`cmake -B build && cmake --build build`)
- Both SuperScalar and CLN's wally must pin the same secp256k1-zkp commit (see `build-plugin.sh` for details)

## Building

Use the included build script:

```bash
# 1. Build CLN (bLIP-56 fork) with musig module enabled
git clone --branch blip-56 https://github.com/8144225309/lightning.git cln-blip56
cd cln-blip56
sed -i 's/\[--enable-module-ecdsa-s2c\]/[--enable-module-ecdsa-s2c], [--enable-module-musig]/' \
  external/libwally-core/configure.ac
./configure && make -j$(nproc)

# 2. Build SuperScalar library
git clone https://github.com/8144225309/SuperScalar.git
cd SuperScalar && cmake -B build && cmake --build build

# 3. Build the plugin
cd /path/to/superscalar-cln
CLN_DIR=/path/to/cln-blip56 SS_DIR=/path/to/SuperScalar ./build-plugin.sh
```

See [`build-plugin.sh`](build-plugin.sh) for full build details including the slim library extraction and symbol rename steps.

## Running

```bash
lightningd --plugin=/path/to/cln-blip56/plugins/superscalar
```

The plugin registers CLN hooks (`custommsg`, `openchannel`, `htlc_accepted`, `block_added`, `connect`) for factory protocol handling, zero-conf channel acceptance, and HTLC safety enforcement.

## RPC Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `factory-create` | `funding_sats`, `clients[]`, `[allocations[]]` | Create a new factory: builds DW tree, generates MuSig2 nonces, sends `FACTORY_PROPOSE` to all clients. Optional `allocations` array specifies per-client sat amounts. |
| `factory-list` | (none) | List all factories with full status (see response schema below) |
| `factory-rotate` | `instance_id` | Advance the Decker-Wattenhofer epoch: STFU quiescence, re-sign tree, send `ROTATE_PROPOSE`, trigger `factory-change` on channels |
| `factory-close` | `instance_id` | Initiate cooperative close: computes distribution outputs, sends `CLOSE_PROPOSE` |
| `factory-force-close` | `instance_id` | Broadcast all signed DW tree transactions for unilateral exit |
| `factory-check-breach` | `instance_id`, `txid`, `vout`, `amount_sats`, `epoch` | Build and broadcast a penalty transaction for a detected breach |
| `factory-open-channels` | `instance_id` | Open Lightning channels inside the factory via `fundchannel_start`/`fundchannel_complete` with factory funding override |
| `factory-forget-channel` | `id`, `channel_id` | Drop a factory channel from CLN without broadcasting a commitment transaction |
| `factory-close-departed` | `instance_id`, `client_idx` | Close a departed client's channel using their extracted key (after key turnover) |
| `factory-confirm-closed` | `instance_id`, `[force]` | Reap a factory the watcher has flagged as closed (lifecycle `closed_externally` or other closed-* state). Removes the factory from memory and deletes its datastore entries. Pass `force=true` to reap regardless of lifecycle — only do this after verifying funds are safe. |
| `factory-scan-external-close` | `instance_id`, `[blocks=1000]` | Manually launch (or re-launch) the Phase 2a spending-TX scan with a configurable block window. Useful when Phase 1's 144-block auto-scan missed the spending TX (e.g., plugin was offline across the close). Populates `spending_txid`, `closed_by`, and may upgrade lifecycle `closed_externally` → `closed_unilateral` if the spender was our own kickoff. |
| `factory-migrate` | `instance_id` | Initiate key turnover for all clients, preparing to move channels to a new factory |
| `factory-migrate-complete` | `instance_id`, `[new_funding_sats]` | Finalize migration after all cooperative clients have departed |
| `factory-buy-liquidity` | `instance_id`, `client_idx`, `amount_sats` | Rebalance L-stock to client on a leaf (requires re-signing) |

### `factory-list` Response Schema

```json
{
  "factories": [{
    "instance_id": "hex",
    "is_lsp": true,
    "n_clients": 3,
    "epoch": 0,
    "n_channels": 3,
    "lifecycle": "active",
    "ceremony": "complete",
    "max_epochs": 16,
    "epochs_remaining": 16,
    "early_warning_time": 2202,
    "creation_block": 300000,
    "expiry_block": 304320,
    "rotation_in_progress": false,
    "n_breach_epochs": 0,
    "dist_tx_status": "signed",
    "tree_nodes": 2,
    "funding_txid": "hex",
    "funding_outnum": 0,
    "channels": [{
      "channel_id": "hex",
      "leaf_index": 1,
      "leaf_side": 0,
      "funding_txid": "hex",
      "funding_outnum": 0
    }]
  }]
}
```

Key fields:
- `early_warning_time` — minimum CLTV headroom (in blocks) for HTLCs on this factory's channels. Derived from the DW tree depth. HTLCs with tighter timeouts are rejected by the `htlc_accepted` hook.
- `epochs_remaining` — rotations left before DW exhaustion triggers migration.
- `lifecycle` — state string. Active factories are `active`; `dying` means a close was initiated; `closed_externally` means the watcher observed the factory root spent without a plugin-initiated close. `closed_unilateral` (populated by Phase 2a) indicates the scan matched our own kickoff TX. `closed_cooperative` / `closed_breached` are reserved for Phase 2b.
- `closed_externally_at_block` — present only when `lifecycle == "closed_externally"`; the block height at which the root-spend was observed.
- `spending_txid` — Phase 2a: hex txid of the TX that spent the factory root, once the scan identifies it.
- `first_noticed_block` — Phase 2a: block height when the UTXO-heartbeat first saw the spend (scan starts here and walks backwards).
- `closed_by` — classification result: `counterparty` (the kickoff or dist TX was published by our peer), `unknown` (scan didn't run or found no matching TX), or (rare, bug-path) `self`. Phase 1 only fires when lifecycle was `ACTIVE`, so the normal label is `counterparty`.
- `dist_signed_txid` — Phase 2b: precomputed segwit txid of our distribution TX (the cooperative close). When a spending TX matches this, lifecycle is set to `closed_cooperative`.
- `breach_epoch` — Phase 2b: populated only when `lifecycle == "closed_breached"` — identifies which revoked epoch's kickoff was published. Phase 3 uses this to select the correct revocation secret for the penalty pathway.
- `kickoff_sig_history_epochs_cached` — Phase 2b diagnostic: how many past epochs' kickoff witness sigs have been captured. Grows on each rotation. Factories pre-dating the Phase 2b upgrade start at 0 and can only classify current-epoch / cooperative-close publishing, not breach.

## Architecture

CLN handles channels. The plugin handles the factory.

- **Inbound**: Factory protocol messages arrive from peers via the `custommsg` hook (ODD message type 33001) and are demultiplexed by submessage ID
- **Outbound**: The plugin sends factory messages via `sendcustommsg` — no new BOLT peer wire message types needed
- **Channel opening**: Factory channels are opened with `fundchannel_start`/`fundchannel_complete`, with `factory_funding_txid` override to reference the DW tree leaf outpoint
- **State changes**: Factory rotation triggers STFU quiescence in channeld, then `factory-change` RPC updates the channel's funding outpoint with batch `commitment_signed` (signing against both old and new outpoints simultaneously)
- **Persistence**: Factory state (metadata, channels, breach data, signed DW tree transactions) is serialized to CLN's datastore under `superscalar/factories/{instance_id}/`. Both LSP and client persist independently for trustless unilateral exit.
- **Tree reconstruction**: On restart, factory trees are rebuilt from persisted metadata + participant pubkeys. Signed transactions are loaded from datastore so `factory-force-close` works immediately after restart.
- **HTLC safety**: The `htlc_accepted` hook rejects incoming HTLCs whose CLTV timeout doesn't leave enough headroom for the factory's DW tree to fully unwind via force-close.

### Wire Protocol

All peer-to-peer factory traffic rides a single **ODD** custommsg type (`33001`) carrying the bLIP-56 `factory_piggyback` envelope. The layering:

```
┌─ CLN custommsg ────────────────────────────────────────────────────┐
│  u16 message_type = 33001 (ODD)                                     │
├─ bLIP-56 envelope (generic across all factory styles) ─────────────┤
│  u16 factory_submessage_id                                          │
│    │  0x0002 supported_factory_protocols (discovery)                │
│    │  0x0004 factory_piggyback          (protocol-specific wrapper) │
│    │  0x0006–0x000C  factory_change_*   (rotation coordination)     │
│  TLV stream                                                         │
│    │  TLV 0    (len 32) factory_protocol_id                         │
│    │  TLV 1024        factory_piggyback_payload (opaque)            │
├─ SuperScalar payload (opaque to bLIP-56, owned by this plugin) ─────┤
│  u16 app_submsg_id (see ceremony.h SS_SUBMSG_*)                     │
│    │  FACTORY_PROPOSE / NONCE_BUNDLE / ALL_NONCES / PSIG_BUNDLE     │
│    │  FACTORY_READY / ROTATE_PROPOSE / REVOKE / REVOKE_ACK          │
│  <app-specific bytes>                                               │
└────────────────────────────────────────────────────────────────────┘
```

**Why ODD 33001 (not the draft's EVEN 32800):** CLN's plugin API dispatches only ODD custom types to plugins, and feature-bit 270/271 negotiation already provides the must-understand guarantee that EVEN was intended to supply. This follows bLIP-17 (Hosted Channels) precedent, which uses only ODD types for a feature-bit-gated plugin-implemented state-machine protocol. See the [fork README](https://github.com/8144225309/lightning/tree/blip-56#bLIP-56-Wire-Protocol) for the full rationale; this is proposed upstream as feedback on [bLIP-56 PR #56](https://github.com/lightning/blips/pull/56).

**`factory_protocol_id` value:** This plugin's SuperScalar protocol id is the 32-byte constant `"SuperScalar/v1"` padded with zeros, i.e. hex `5375706572536361 6c61722f763100000000000000000000 00000000000000000000000000000000`. Carried in TLV 0 of every `factory_piggyback` envelope; receivers ignore messages whose protocol id doesn't match their supported set.

**Per-protocol submessage namespace:** `app_submsg_id` values inside `factory_piggyback_payload` are scoped to this `factory_protocol_id`. Different factory protocols may reuse the same `app_submsg_id` numbers without collision because the outer `factory_protocol_id` routes to the correct handler.

### Factory Creation Ceremony (MuSig2)

Factory creation is a multi-round MuSig2 protocol between 1 LSP and N clients:

1. **`FACTORY_PROPOSE`** (LSP → Clients): LSP builds DW tree, generates nonces, sends nonce bundle
2. **`NONCE_BUNDLE`** (Clients → LSP): Clients build identical tree, generate their nonces, send back
3. **`ALL_NONCES`** (LSP → Clients): LSP aggregates all nonces, sends combined bundle so clients can finalize and create partial signatures
4. **`PSIG_BUNDLE`** (Clients → LSP): Clients send partial signatures
5. **`FACTORY_READY`** (LSP → Clients): LSP aggregates into final Schnorr signatures, co-signs distribution TX, ceremony complete

### Factory Lifecycle

`INIT` → `ACTIVE` → `DYING` → `EXPIRED`

Ceremony states: `IDLE` → `PROPOSED` → `NONCES_COLLECTED` → `PSIGS_COLLECTED` → `COMPLETE`

## Why the bLIP-56 Fork is Required

This plugin depends on channel-management changes in the [bLIP-56 CLN fork](https://github.com/8144225309/lightning/tree/blip-56).

Fork changes needed by the plugin:
- **Feature bit 270/271** (`pluggable_channel_factories`) — advertised in `init` for peer discovery
- **TLV 65600** (`channel_in_factory`) on `open_channel`/`accept_channel` — carries factory protocol ID, instance ID, and early warning time
- **`fundchannel_start` factory params** — `factory_protocol_id`, `factory_instance_id`, `factory_early_warning_time` populate TLV 65600
- **`fundchannel_complete` override** — `factory_funding_txid` param to reference DW tree leaf outpoint
- **`factory-change` RPC** — STFU quiescence + batch `commitment_signed` for channel funding outpoint update after rotation
- **`factory-forget-channel` RPC** — drop a channel without commitment broadcast
- **`checkutxo` RPC** — UTXO status query for breach detection
- **Zero-conf** — `openchannel` hook returns `mindepth=0` for factory peers; skip funding watch for virtual outpoints

Without the fork, the plugin cannot open factory channels with virtual funding outpoints or update them after rotation.

## Related Projects

| Project | Description |
|---------|-------------|
| [SuperScalar](https://github.com/8144225309/SuperScalar) | Reference implementation of the SuperScalar protocol |
| [lightning (bLIP-56 fork)](https://github.com/8144225309/lightning/tree/blip-56) | Core Lightning fork with pluggable channel factory support |
| [superscalar-wallet](https://github.com/8144225309/superscalar-wallet) | Web-based wallet UI for SuperScalar factory management |
| [superscalar-docs](https://github.com/8144225309/superscalar-docs) | Protocol documentation and visual guides |
| [superscalar.win](https://superscalar.win) | SuperScalar explainer and documentation site |

## License

MIT
