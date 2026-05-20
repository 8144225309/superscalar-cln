# Signing Availability Protocol

**Status:** v1 draft · 2026-05-20
**Scope:** how a SuperScalar LSP and its participating clients coordinate
factory-signing ceremonies across intermittent client connectivity, and
how the wallet UX handles the auto-sign / ask-me-each-time choice.

This document captures the decisions made in the Phase B design
conversation and informs Phase D implementation work (auto-sign
toggle, LSP queue, missed-ceremony notification).

---

## 1. The problem

bLIP-56 ceremony messages ride BOLT-1 custommsg over a direct BOLT-8
peer connection.  That transport requires both peers online at the same
time.  Real clients — phones, laptops, hot wallets — are intermittently
online.

Concrete cases the LSP must handle:

| Case | Client state |
|---|---|
| A | Online, auto-sign **ON** → signs immediately on validator pass |
| B | Online, auto-sign **OFF** → plugin holds proposal, user decides via wallet UI |
| C | Offline at proposal time, comes back within the LSP's deadline |
| D | Offline through the LSP's deadline → missed this ceremony |

Today (post-Phase B) only case **A** is fully wired.  This document
defines how B, C, and D should work.

---

## 2. Core design principle: LSP is the source of truth

The LSP owns the ceremony schedule, the participant list, the deadline,
and the per-peer signing queue.  The client is a stateless responder:
when it's online and BOLT-8-peered with an LSP, it asks the LSP "do you
have anything for me?" and acts on whatever the LSP says.

This is intentionally simpler than symmetric or push-based protocols.
Three concrete implications:

- **No client → LSP "going-offline" announcement.**  The client doesn't
  need to say "I'm going offline at block N."  The LSP infers
  unavailability from BOLT-8 disconnect or failed delivery attempts.
  No new wire message for offline hints — that's an explicit
  non-feature.
- **No client-side ceremony queue.**  When the client comes online and
  pulls from the LSP, whatever the LSP has is the authoritative state.
  The client doesn't try to remember what it might have missed; it asks.
- **LSP-side per-peer queue is load-bearing.**  Per (lsp_peer_id,
  factory_instance_id) the LSP must remember whether each client's
  signature is still outstanding, whether the ceremony deadline has
  passed, and the proposal blob needed for the client to render its
  review modal on reconnect.

---

## 3. The five client outcomes per ceremony

The LSP tracks, per (factory_instance_id, client_peer_id, ceremony_id):

| State | Meaning |
|---|---|
| **AWAITING_YOUR_SIGNATURE** | Proposal sent, waiting on the client |
| **SIGNED** | Client's signature received in time |
| **MISSED** | Ceremony advanced without this client; LSP proceeded with the remaining quorum |
| **REFUSED** | Client explicitly refused via `factory-refuse-proposal` |
| **EXPIRED** | Deadline passed before quorum; ceremony itself aborted |

States 3-5 are terminal for that ceremony.  Subsequent ceremonies
(rotations) start fresh.

---

## 4. Wire protocol additions

Two new submessages under the SuperScalar factory envelope (33001):

### 4.1  `SS_SUBMSG_SIGN_QUEUE_REQUEST` (proposed: 0x014D)

Client → LSP.  Sent automatically by the plugin immediately after a
BOLT-8 handshake completes with an LSP the client has interacted with
before.  No user action; this is a routine reconnect query.

Payload (TLV stream):

| TLV | Field | Type | Notes |
|---|---|---|---|
| 0x00 | factory_instance_id | 32 bytes | Optional; absent = "all my factories" |
| 0x01 | since_block | u32 | Optional; only return entries newer than this |

### 4.2  `SS_SUBMSG_SIGN_QUEUE_RESPONSE` (proposed: 0x014E)

LSP → client.  TLV stream containing zero or more entries:

| TLV | Field | Type |
|---|---|---|
| 0x00 | factory_instance_id | 32 bytes |
| 0x01 | ceremony_id | 8 bytes |
| 0x02 | state | u8 (per §3) |
| 0x03 | deadline_block | u32 |
| 0x04 | proposal_blob | bytes (only if state requires user action, i.e. AWAITING_YOUR_SIGNATURE) |
| 0x05 | missed_reason | u8 (only if state = MISSED) |

The LSP enumerates only ceremonies where the client was a participant.
Entries can be filtered by `since_block` to bound the response size.

### 4.3  Why no re-broadcast of `FACTORY_PROPOSE`

If the LSP has already started the ceremony and proceeded past
`NONCES_COLLECTED` for a client that wasn't online, it cannot
incorporate that client's signature anyway — the round is done.  The
LSP returns `state=MISSED` with the proposal blob omitted and moves on.
No need to re-deliver the original `FACTORY_PROPOSE`.

---

## 5. LSP-side queue semantics

Stored in the wallet daemon SQLite (or libsuperscalar SQLite while the
wallet daemon split is being finished — see CONFORMANCE):

```sql
CREATE TABLE pending_signature_queue (
  factory_instance_id  BLOB    NOT NULL,
  client_peer_id       BLOB    NOT NULL,
  ceremony_id          BLOB    NOT NULL,
  state                INTEGER NOT NULL,  -- 0..4 per §3
  deadline_block       INTEGER NOT NULL,
  proposal_blob        BLOB,              -- last known FACTORY_PROPOSE bytes
  inserted_at_block    INTEGER NOT NULL,
  delivered_at_block   INTEGER,           -- when LSP last attempted send
  responded_at_block   INTEGER,
  PRIMARY KEY (factory_instance_id, client_peer_id, ceremony_id)
);
```

### 5.1  Eviction

- On client signature received: state = SIGNED, retain for 1008 blocks
  (≈ 1 week) so a reconnect query can confirm.
- On `factory-refuse-proposal`: state = REFUSED, retain 1008.
- On `deadline_block` reached without enough signatures: state =
  EXPIRED, ceremony itself aborts.
- When `current_block > deadline_block + 1008`: row deleted.

### 5.2  Delivery timing

- LSP attempts `FACTORY_PROPOSE` over BOLT-1 immediately when the
  ceremony starts.
- If the BOLT-8 peer is connected: state stays
  AWAITING_YOUR_SIGNATURE; LSP waits for client response.
- If the BOLT-8 peer is disconnected: LSP logs the attempt + does NOT
  retry eagerly.  The client will issue `SIGN_QUEUE_REQUEST` on its
  next BOLT-8 handshake (auto-initiated by the client plugin), and the
  LSP will hand over the still-fresh proposal_blob then.  No retry
  storm.
- On reaching `deadline_block`: if a quorum signed, mark missing
  clients MISSED and proceed.  If quorum not met, mark everyone
  EXPIRED and abort.

### 5.3  No re-broadcast on reconnect

The LSP MUST NOT eagerly re-send `FACTORY_PROPOSE` when the peer
reconnects.  It waits for the client's `SIGN_QUEUE_REQUEST` and
responds with the cached blob.  Two reasons:

1. Predictable behaviour: clients never receive a stale PROPOSE for an
   already-decided ceremony.
2. Avoids the "client gets the same proposal three times" UX surprise.

---

## 6. Client-side flow on reconnect

```
BOLT-8 handshake completes with LSP P
        ↓
plugin auto-fires SIGN_QUEUE_REQUEST (no instance_id — get all)
        ↓
LSP responds with N entries
        ↓
for each entry:
    if state == AWAITING_YOUR_SIGNATURE:
        same handler path as a fresh FACTORY_PROPOSE:
          cache in pending_proposals,
          run validator,
          branch on auto_sign_on_validator_pass toggle
          (§7 below)
    if state == MISSED || EXPIRED:
        emit a one-shot wallet notification (see §8.2)
        keep in pending_proposals cache for read-only review
    if state == SIGNED:
        confirm our local record matches; no UI change
```

The client doesn't need a persistent local queue — every interesting
state is on the LSP and re-fetched on reconnect.

---

## 7. Auto-sign toggle

New field on `ss_client_signing_prefs_t` (`factory_policy.h`):

```c
bool auto_sign_on_validator_pass;  /* default true */
```

Exposed in the wallet UI at `/factories/signing-prefs` as a top-of-page
toggle:

```
[x] Sign automatically when policy passes validation
    Recommended for most users.  When OFF, every factory proposal
    will pop up a review modal asking you to confirm before signing.
```

### 7.1  Behaviour when ON (default)

Existing behaviour: validator runs, on OK → generate nonces immediately
→ continue ceremony.  HARD_FAIL → drop.

### 7.2  Behaviour when OFF

Validator runs as usual.  On HARD_FAIL → drop (no change — toggle does
not loosen security).

On OK:
1. Plugin stashes the proposal in `pending_proposals` (already happens).
2. Plugin does **not** send `NONCE_BUNDLE`.
3. The wallet UI sees a new client-side factory in `lifecycle=init,
   ceremony=proposed` and surfaces a sticky notification:

   ```
   ⚠ Factory abc123def456 is awaiting your approval — review and sign?
                                                            [Review]
   ```

4. User clicks Review → existing B4 modal opens with the full proposal
   data (allocations, advertised policy vs prefs, validator outcome).
5. User clicks **Approve & sign** → plugin RPC
   `factory-approve-proposal` releases the held nonces; the ceremony
   continues.
6. User clicks **Refuse** → plugin RPC `factory-refuse-proposal`
   marks the proposal REFUSED and (once PR 3c lands at task #81)
   sends `CEREMONY_ABORT` (submsg 0x0149).

The proposal blob lives in `pending_proposals` until the LSP's deadline
or the user decides.  If the user is still offline when the deadline
hits, the LSP marks them MISSED and proceeds without them.

---

## 8. Wallet UX

### 8.1  Signing preferences page

`/factories/signing-prefs` gains the auto-sign toggle at the top, above
the existing 13 threshold fields.

### 8.2  Missed-ceremony banner

When the wallet receives a `SIGN_QUEUE_RESPONSE` containing entries
with `state=MISSED` or `state=EXPIRED`, the FactoriesHome page shows a
one-time dismissible banner per entry:

```
You were offline during the signing of factory abc123def456
(epoch 4, expired at block 305299).  You have been skipped from
this ceremony — your stake from the previous epoch carries forward.
                                              [Dismiss] [Audit details]
```

"Audit details" opens the existing B4 review modal in read-only mode so
the user can see exactly what the proposal would have been.

### 8.3  Sticky pending-review notification

When `auto_sign_on_validator_pass=false` and a `FACTORY_PROPOSE`
arrives (live or via `SIGN_QUEUE_RESPONSE`), the FactoriesHome page
shows a sticky banner at the top, persistent until the user decides:

```
⚠ Factory abc123def456 is awaiting your approval — review and sign?
                                                            [Review]
```

Closing the modal without deciding does not dismiss the banner.  Only
Approve or Refuse clears it.

---

## 9. Plugin state machine impact

Today's `FACTORY_PROPOSE` handler:

```
validator OK   → generate nonces → send NONCE_BUNDLE  (auto-sign)
validator FAIL → drop
```

After Phase D:

```
validator OK + auto_sign=ON   → generate nonces → send NONCE_BUNDLE
validator OK + auto_sign=OFF  → cache proposal → wait for factory-approve
validator FAIL                → drop  (no change)
                              → optionally send CEREMONY_ABORT after PR 3c
```

The existing `pending_proposals` cache stays the same shape; we add a
flag column `waiting_user_decision` so the `SIGN_QUEUE_REQUEST` reply
includes only entries the user actually still needs to decide on.

---

## 10. Phase D delivery plan

| Step | Scope | Lands in |
|---|---|---|
| D.1 | Add `auto_sign_on_validator_pass` to prefs + plugin gate the auto-sign path | superscalar-cln + superscalar-wallet |
| D.2 | LSP-side `pending_signature_queue` table + retry timer | superscalar-cln |
| D.3 | `SIGN_QUEUE_REQUEST` / `_RESPONSE` wire pair (submsg 0x014D / 0x014E) | superscalar-cln |
| D.4 | Client-side: pull on reconnect, fan-out to per-state handlers | superscalar-cln |
| D.5 | Wallet UX: toggle + missed-banner + sticky review prompt | superscalar-wallet |
| D.6 | Auto-sign-off makes `factory-approve-proposal` / `refuse-proposal` load-bearing (kill the advisory-ack stub) | superscalar-cln |

D.1 alone unlocks the user-toggleable behaviour for **online** clients.
D.2 + D.3 + D.4 close the offline-reconnect loop.  D.5 is the wallet
UI.  D.6 finalizes by replacing the current advisory-only
approve/refuse with real load-bearing RPCs.

---

## 11. Open questions, intentionally out of scope for V1

These are NOT decided in this draft:

- **Mobile push wake-up.**  Out of scope.  Clients learn about pending
  signings via `SIGN_QUEUE_REQUEST` after they're online-and-peered.
  Push notifications (so the user opens the app proactively) are a
  layer above this protocol — handled by phone-OS infrastructure, not
  by SuperScalar.
- **Multi-LSP coordination.**  If a client participates in factories
  at multiple LSPs, it sends `SIGN_QUEUE_REQUEST` to each on reconnect.
  Both may have pending entries.  No cross-LSP coordination; each LSP
  ↔ client pair is independent.
- **Deadline tuning.**  How long should an LSP wait for an offline
  client?  Suggested default: 6 blocks (≈ 1 hour on mainnet) after which
  the client is skipped.  Configurable via `lsp_operator_prefs`
  per-factory.  Whether shorter deadlines are reasonable is a
  UX-vs-throughput tradeoff for the LSP operator, not a protocol
  decision.
- **Ephemeral per-factory node_ids.**  Privacy-improvement covered in
  PROTOCOL_NOTES.md §8.  Orthogonal to this protocol.

---

## 12. References

- bLIP-56 PR — wire envelope spec
- FACTORY_POLICY_V1.md — what the validator checks before signing
- PROTOCOL_NOTES.md §6 — ceremony lifecycle states
- PROTOCOL_NOTES.md §8 — privacy & Tor (this protocol does not weaken)
- `superscalar-cln` PR #63 — B1.5 validator + factory-review-proposal
  + client-signing-prefs RPCs + send_factory_msg auto-reconnect (#123)
- `superscalar-wallet` PR #33 — B3 signing preferences editor
- `superscalar-wallet` PR #35 — B4 pre-sign confirmation modal
