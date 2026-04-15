# superscalar-cln

SuperScalar channel factory plugin for [Core Lightning](https://github.com/ElementsProject/lightning). Implements [bLIP-56](https://github.com/lightning/blips/pull/56) (pluggable channel factories) using Decker-Wattenhofer state trees with MuSig2 signing.

This plugin enables a Core Lightning node to participate in [SuperScalar](https://github.com/8144225309/SuperScalar) channel factories — shared UTXOs that give multiple users non-custodial Lightning channel access in a single on-chain transaction. For a detailed explanation of the protocol, visit [superscalar.win](https://superscalar.win).

## Requirements

- [Core Lightning (bLIP-56 fork)](https://github.com/8144225309/lightning/tree/blip-56) — the `blip-56` branch with minimal channel-management changes for factory support (no new wire types, TLVs, or feature bits)
- Bitcoin Core 28+
- `libsuperscalar_core.a` (static library from the [SuperScalar](https://github.com/8144225309/SuperScalar) build)
- `libsecp256k1` with extrakeys module

## Building

The plugin builds inside the CLN source tree:

```bash
# Clone CLN with bLIP-56 support
git clone --branch blip-56 https://github.com/8144225309/lightning.git cln-blip56
cd cln-blip56
./configure && make -j$(nproc)

# Copy plugin source and build
cp /path/to/superscalar-cln/superscalar.c plugins/
make plugins/superscalar
```

## Running

```bash
lightningd --plugin=/path/to/cln-blip56/plugins/superscalar
```

The plugin registers CLN hooks (`custommsg`, `openchannel`, `block_added`, `connect`) for factory protocol handling and zero-conf channel acceptance.

## RPC Methods

The plugin exposes seven JSON-RPC methods through CLN's standard interface:

| Method | Parameters | Description |
|--------|-----------|-------------|
| `factory-create` | `funding_sats`, `clients` (array of node IDs) | Create a new factory: builds DW tree, generates MuSig2 nonces, sends `FACTORY_PROPOSE` to all clients |
| `factory-list` | (none) | List all factories with full status (see response schema below) |
| `factory-rotate` | `instance_id` | Advance the Decker-Wattenhofer epoch: rebuilds tree transactions with new nonces, sends `ROTATE_PROPOSE` |
| `factory-close` | `instance_id` | Initiate cooperative close: computes distribution outputs, sends `CLOSE_PROPOSE` |
| `factory-force-close` | `instance_id` | Broadcast all signed DW tree transactions for unilateral exit, force-closes associated LN channels |
| `factory-check-breach` | `instance_id`, `txid`, `vout`, `amount_sats`, `epoch` | Build and broadcast a penalty/burn transaction for a detected breach (old-epoch state on-chain) |
| `factory-open-channels` | `instance_id` | Open Lightning channels inside the factory via `fundchannel_start`/`fundchannel_complete` with factory funding override |

### `factory-list` Response Schema

```json
{
  "factories": [{
    "instance_id": "hex",       // 32-byte factory identifier
    "is_lsp": true,             // whether this node is the LSP
    "n_clients": 3,             // number of client participants
    "epoch": 0,                 // current DW epoch (increments on rotation)
    "n_channels": 3,            // number of open LN channels in factory
    "lifecycle": "active",      // init | active | dying | expired
    "ceremony": "complete",     // idle | proposed | nonces_collected | psigs_collected | complete | rotating | rotate_complete | revoked | failed
    "max_epochs": 256,          // total DW states before factory exhaustion
    "creation_block": 14195,    // block height when factory was created
    "expiry_block": 18515,      // absolute block height of factory CLTV timeout
    "rotation_in_progress": false,
    "n_breach_epochs": 0,       // number of stored breach/revocation records
    "dist_tx_status": "signed", // none | unsigned | signed | unknown
    "tree_nodes": 6,            // total nodes in DW tree (persisted across restarts)
    "funding_txid": "hex",      // factory-level synthetic funding UTXO
    "funding_outnum": 0,
    "channels": [{
      "channel_id": "hex",      // CLN channel_id
      "leaf_index": 3,          // DW tree node index for this channel's leaf
      "leaf_side": 0,           // output index within the leaf (for arity-2 shared leaves)
      "funding_txid": "hex",    // real DW leaf node txid (the on-chain enforceable outpoint)
      "funding_outnum": 0       // output index on the leaf transaction
    }]
  }]
}
```

The wallet can cross-reference `channels[].channel_id` against CLN's `listpeerchannels` to get per-channel spendable/receivable balances, connection state, and creation timestamps.

## Architecture

CLN handles channels. The plugin handles the factory.

- **Inbound**: Factory protocol messages arrive from peers via the `custommsg` hook (ODD message type 33001) and are demultiplexed by submessage ID
- **Outbound**: The plugin sends factory messages via `sendcustommsg` — no CLN wire protocol changes needed (ODD types pass through connectd by default)
- **Channel opening**: Factory channels are opened with `fundchannel_start`/`fundchannel_complete`, with `factory_funding_txid` override to reference the DW tree leaf outpoint
- **State changes**: Factory rotation triggers `factory-change` RPC in the CLN fork, which updates the channel's funding outpoint internally
- **Persistence**: Factory state is serialized to CLN's datastore under `superscalar/factories/{instance_id}/`

### Factory Creation Ceremony (MuSig2)

Factory creation is a 3-round MuSig2 protocol between 1 LSP and N clients:

1. **`FACTORY_PROPOSE`** (LSP -> Clients): LSP builds DW tree, generates nonces, sends nonce bundle
2. **`NONCE_BUNDLE`** (Clients -> LSP): Clients build identical tree, generate their nonces, send back. In 2-party mode, clients also send partial signatures in the same round
3. **`PSIG_BUNDLE`** (Clients -> LSP): LSP aggregates nonces and partial sigs into final Schnorr signatures, then co-signs the distribution TX and sends `FACTORY_READY`

### Factory Lifecycle

`INIT` -> `ACTIVE` -> `DYING` -> `EXPIRED`

Ceremony states: `IDLE` -> `PROPOSED` -> `NONCES_COLLECTED` -> `PSIGS_COLLECTED` -> `COMPLETE`

## Why the bLIP-56 Fork is Required

This plugin depends on channel-management changes in the [bLIP-56 CLN fork](https://github.com/8144225309/lightning/tree/blip-56). The fork adds **zero new LN network messages** — factory protocol runs via ODD custommsg (type 33001).

Fork changes needed by the plugin:
- **`fundchannel_complete` override** — `factory_funding_txid` param to reference DW tree leaf outpoint
- **`factory-change` RPC** — updates channel funding outpoint after factory rotation
- **`fundchannel_complete` override** — `factory_funding_txid` param to reference DW tree leaf outpoint
- **Zero-conf** — `openchannel` hook returns `mindepth=0` for factory peers; skip funding watch for virtual outpoints
- **`checkutxo` RPC** — UTXO status query for breach detection

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
