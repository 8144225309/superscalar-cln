# bLIP-56 Conformance

How this implementation maps to the [bLIP-56 draft spec](https://github.com/lightning/blips/pull/56) (Pluggable Channel Factories).

Status columns:
- **✓ Conformant** — implements the draft as written
- **△ Conformant with deviation** — implements the spec's intent via a documented, rationale-backed change
- **○ Out of scope** — not implemented by design
- **– Not yet** — planned, not built

## Wire Protocol

| Spec item | Status | Notes |
|---|---|---|
| Feature bit `pluggable_channel_factories` (270/271) | ✓ | Advertised in `init` and `node_announcement` via `common/features.h` |
| `factory_message_id` custom peer wire type | △ | Draft specifies 32800 EVEN. Fork uses **ODD 33001**. Rationale below. |
| `factory_submessage_id` dispatch inside envelope | ✓ | u16 after the wire-type prefix |
| `factory_piggyback` envelope (submsg 0x0004) | ✓ | TLV 0 = protocol_id, TLV 1024 = piggyback_payload |
| `supported_factory_protocols` handshake (submsg 0x0002) | ✓ | Sent in `connect` handler, received via custommsg |
| TLV 65600 `channel_in_factory` on `open_channel` / `accept_channel` | ✓ | Carries `factory_protocol_id`, `factory_instance_id`, `factory_early_warning_time` |
| Factory-channel zero-conf (`minimum_depth=0`) | ✓ | Via `OPT_ZEROCONF` and `openchannel` hook |
| Skip on-chain funding watch for factory channels | ✓ | `has_factory` flag in opening control |

### Deviation: ODD 33001 instead of EVEN 32800

**What:** All factory peer-to-peer traffic rides ODD custommsg type 33001 rather than the draft's EVEN 32800.

**Why:**
1. CLN's plugin API dispatches only ODD custom message types to plugins. Using EVEN would force fork-level core code to handle every factory message, defeating the "pluggable" design intent.
2. Feature bit 270/271 negotiation already establishes mutual must-understand semantics between participants. EVEN's disconnect-on-unknown rule adds no protection on top of feature-bit gating for a protocol scoped to advertised participants.
3. bLIP-17 (Hosted Channels) sets a direct precedent: a feature-bit-gated, consensus-critical, plugin-implemented state machine using entirely ODD custom types (63497–65535).
4. Non-factory peers never observe factory traffic. Sub-channels use alias scids (BOLT 2 private-channel mechanism), routing is standard BOLT 2, force-close is participant-local. Factory-ness is fully encapsulated at the participant boundary.

**Migration plan:** If bLIP-56 ratifies on a specific ODD value, one `#define` change in the plugin realigns. If it insists on EVEN, the fork can add a translation layer (EVEN 32800 on wire ↔ ODD 33001 to plugin) without disturbing the plugin. Currently provisional pending spec engagement on PR #56.

## Submessages Implemented

### bLIP-56 generic (cross-protocol, layer-2 in our architecture)

| Submsg ID | Name | Direction | Status |
|---|---|---|---|
| 0x0002 | `supported_factory_protocols` | Both | ✓ Sent on connect; TLV 512 lists supported protocol ids |
| 0x0004 | `factory_piggyback` | Both | ✓ Opaque wrapper for protocol-specific traffic |
| 0x0006 | `factory_change_init` | Initiator → Responder | ✓ STFU-gated rotation init |
| 0x0008 | `factory_change_ack` | Responder → Initiator | ✓ Rotation acknowledgment |
| 0x000A | `factory_change_funding` | Both | ✓ New funding txid exchange |
| 0x000C | `factory_change_continue` | Initiator → Responder | ✓ Resume from STFU after new state valid |

### SuperScalar-specific (inside `factory_piggyback_payload`)

`factory_protocol_id = 0x5375706572536361 6c61722f76310000…` (ASCII "SuperScalar/v1" zero-padded to 32 bytes).

| `app_submsg_id` | Name | Direction | Status |
|---|---|---|---|
| `SS_SUBMSG_FACTORY_PROPOSE` | Factory creation init + nonces | LSP → Clients | ✓ |
| `SS_SUBMSG_NONCE_BUNDLE` | Client-side MuSig2 round 1 | Client → LSP | ✓ |
| `SS_SUBMSG_ALL_NONCES` | Aggregated nonce broadcast | LSP → Clients | ✓ |
| `SS_SUBMSG_PSIG_BUNDLE` | MuSig2 round 2 partial sigs | Client → LSP | ✓ |
| `SS_SUBMSG_FACTORY_READY` | Ceremony complete, final sigs + distribution TX | LSP → Clients | ✓ |
| `SS_SUBMSG_ROTATE_PROPOSE` | Epoch rotation kickoff | LSP → Clients | ✓ |
| `SS_SUBMSG_REVOKE` | Prev-epoch revocation secret handoff | LSP → Clients | ✓ |
| `SS_SUBMSG_REVOKE_ACK` | Durable receipt of revocation | Clients → LSP | ✓ |
| `SS_SUBMSG_CLOSE_PROPOSE` | Cooperative close init | LSP → Clients | ✓ |
| `SS_SUBMSG_MIGRATE_*` | Key turnover flow | Either | ✓ |

Full list in `ceremony.h`.

## Feature-Bit Gating

Every factory-specific message path is gated on feature bit 270/271 being mutually negotiated:

- TLV 65600 is set on `open_channel` only when the peer advertised 270/271 (else fall back to normal channel open).
- `supported_factory_protocols` exchange happens only on peers that advertise 270/271 at `init`.
- `factory_piggyback` is sent only after `supported_factory_protocols` confirms the peer also supports at least one common `factory_protocol_id`.
- No factory traffic is ever sent to non-factory peers.

This is the property that makes ODD-wire-type safe: every factory message is between two peers who've both committed to handling it.

## Known Gaps vs. bLIP-56 Draft

| Item | Gap | Mitigation |
|---|---|---|
| `factory_protocol_id` registration in bLIP-2 | Not yet filed | Will accompany the PR #56 comment proposing the ODD wire type |
| Custom wire type registration in bLIP-2 | Not yet filed | 33001 is provisional; may shift to whatever PR #56 lands on |
| `-Wunused-result` on 2 lines in `superscalar.c` | Warnings not errors | Build succeeds, tests pass; non-blocking follow-up |

## Deliberate Non-Goals

These are deviations from bLIP-56 by design, not oversight:

- **No EVEN wire message type added.** The draft's 32800 is solving a problem (cross-implementation must-understand for discovery) that feature-bit negotiation already solves. Adding an EVEN type would increase fork divergence without buying safety.
- **No public gossip announcement of factory sub-channels.** Sub-channels use alias scids; routing via invoice hints / blinded paths. This is how private channels already work in BOLT 2; no new machinery required.
- **No new gossip message types.** The rest of the LN network sees a factory node as a normal node with normal channels. Factory state is entirely a participant-local concern.

## Testing

Smoke tests live in `tests/test_smoke.py` and `tests/signet/`. `make test` runs the pyln-testing regtest suite with the correct environment variables (`LIGHTNINGD`, `SUPERSCALAR_PLUGIN`, `PATH`) pointing at the fork build.

As of the last run: **4/4 smoke tests passing.** Includes two-node connect + protocol discovery (end-to-end exercise of the `supported_factory_protocols` handshake).

## Status

- **Implementation:** ~90% of the bLIP-56 draft's wire-visible surface, with the one well-documented deviation on wire-type parity.
- **Spec engagement:** pending. Plan: post implementation feedback on PR #56 citing bLIP-17 precedent, propose ODD ratification, offer this repo as reference implementation.
- **Second implementation:** not yet. bLIP ratification typically requires two; LDK is the most plausible next target after CLN.

## Trustless watcher (Phase 1 shipped)

Factory lifecycle is observed against on-chain truth so records can't drift into zombies when a factory is closed outside the plugin. See [project_trustless_watcher_plan.md](#) (4-phase plan) for the full design.

| Watcher capability | Status |
|---|---|
| UTXO heartbeat on `block_added` + startup catch-up | ✓ Phase 1 |
| `CLOSED_EXTERNALLY` lifecycle state on unexpected root spend | ✓ Phase 1 |
| `factory-confirm-closed` RPC for explicit operator reap | ✓ Phase 1 |
| Bounded block scan to identify the spending TX | ✓ Phase 2a |
| Self-close detection (our kickoff → `CLOSED_UNILATERAL`) | ✓ Phase 2a |
| `factory-scan-external-close` RPC (operator re-scan with wider window) | ✓ Phase 2a |
| Counterparty-normal vs breach distinction (witness-sig match against cached per-epoch sigs) | ✓ Phase 2b |
| Cooperative close detection (precomputed `dist_signed_txid` match) | ✓ Phase 2b |
| Per-epoch kickoff signature snapshot at rotation | ✓ Phase 2b |
| Automated breach penalty construction + fee bumping | — Phase 3 |
| Multi-party ceremony tests at N > 2 | — Phase 4 |
