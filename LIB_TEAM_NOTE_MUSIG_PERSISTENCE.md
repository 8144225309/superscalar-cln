# LIB_TEAM_NOTE: MuSig2 session persistence across plugin restart

Date: 2026-05-20
Author: plugin/wallet AI
For: lib team (task #80)

## Problem statement

libsuperscalar's `factory_t` and its embedded `signing_session_t`
state are held entirely in memory. When the bLIP-56 plugin restarts
mid-ceremony, the persisted `factory_instance_t` (from the wallet
SQLite) reloads with its lifecycle/ceremony state intact, but the
in-memory MuSig2 session data is lost.

The plugin then either:

1. Tries to continue and calls `factory_sessions_finalize()` on an
   empty session_t — this fails noisily.
2. Receives retransmitted NONCE_BUNDLE / PSIG_BUNDLE messages from
   reconnecting peers (whose own state thinks the ceremony is still
   running) — same broken finalize path on each retry.

## Symptoms observed

Repeated `BROKEN plugin-superscalar: factory_sessions_finalize failed`
log lines after every plugin restart that has factories in:

  - CEREMONY_PROPOSED
  - CEREMONY_FUNDING_PENDING
  - CEREMONY_NONCES_COLLECTED
  - CEREMONY_PSIGS_COLLECTED
  - CEREMONY_ROTATING

Quiesced factories (COMPLETE / ROTATE_COMPLETE / REVOKED) still receive
stale NONCE_BUNDLEs from reconnecting clients and hit the same path.

## Interim mitigation (already shipped)

Commit `55e0311` on `fix/signet-smoke-bugs`:

  - At `ss_load_factories`, any factory loaded with an in-flight
    ceremony state is reset to FAILED + AWAITING_JOINS (LSP side) so
    the operator can re-fire `factory-trigger-ceremony` fresh.
  - At NONCE_BUNDLE / PSIG_BUNDLE LSP handlers, a stale-msg guard
    rejects messages when the factory isn't actively in a matching
    expecting-message state, and sends `CEREMONY_ABORT(OTHER)` to the
    sender so they stop retrying.

This stops the noisy retry loop and surfaces affected factories to
the operator, but it does NOT recover an in-flight ceremony — the
operator must re-run it from scratch.

## What lib task #80 needs

To actually survive restart mid-ceremony, libsuperscalar needs:

1. **Serialize / deserialize** for `signing_session_t` (and any other
   transient MuSig2 state held in `factory_t->nodes[]` after
   `factory_sessions_init` but before `factory_sessions_finalize`):
     - Each node's secnonces (after `musig_nonce_gen` but before
       `factory_sessions_finalize`)
     - Per-signer pubnonces (collected via `set_nonce` calls)
     - Cached aggregated pubnonces / partial signatures
2. **SQLite migration** to libsuperscalar's existing DB schema so the
   plugin doesn't have to know the internal session format — just
   call `factory_persist_sessions(f, tx)` and `factory_restore_sessions(f, tx)`.
3. **Plugin contract**: on restart, instead of resetting to FAILED,
   the plugin would call `factory_restore_sessions()` for every
   factory whose ceremony state is mid-flight, and continue normally.

## How to coordinate

When this lands lib-side, swap the load-time reset block in
`ss_load_factories` (search for `Audit #5 follow-up: reset in-flight
ceremony state`) for the lib's `factory_restore_sessions()` call.
The stale-msg guard can stay as a defense-in-depth check — it's not
specific to the restart bug.

If a more permissive design ends up being workable (e.g. lib can
reconstruct sessions from the nonce_commit / cached nonces alone),
the plugin's flat-file persistence of the LSP signature queue (audit
item #4, `superscalar_lsp_sig_queue.json`) already has every payload
the LSP would need to replay — that's another path forward.
