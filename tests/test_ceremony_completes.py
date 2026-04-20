"""Phase 5b — ceremony-driven regtest E2E tests.

The probe established that a real two-party ceremony completes in ~30s
on regtest. These tests build on that: ceremony completion, factory-
list fields after a real ceremony, and rotation bumping the epoch.

Follow-up tests (force-close → DYING → CPFP; breach → burn confirmed)
can layer on top of this foundation in subsequent PRs.
"""
from __future__ import annotations

import pytest

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)


def _setup_factory(ss_node_factory, funding_sats=100_000):
    """Two plugin-loaded nodes, LSP funded, connected, ceremony run
    to completion. Returns (lsp, client, instance_id)."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def test_two_party_ceremony_reaches_complete(ss_node_factory):
    """LSP + one client, both plugin-loaded. LSP calls factory-create,
    we wait for ceremony=complete. If the custommsg 33001 pipe works
    and both sides cooperate, this should succeed in under a minute."""
    lsp, client, iid = _setup_factory(ss_node_factory)

    out = lsp.rpc.call("factory-list")
    entry = next(f for f in out["factories"]
                 if f["instance_id"] == iid)
    assert entry["ceremony"] == "complete"
    assert entry["lifecycle"] in {"init", "active"}, (
        f"unexpected lifecycle {entry['lifecycle']!r} after ceremony "
        f"complete"
    )


def test_factory_list_fields_after_ceremony(ss_node_factory):
    """After a real ceremony, factory-list exposes the expected
    fields with realistic values (non-zero funding_txid, correct
    participant count, epoch=0). Regression guard against silent
    field drift."""
    lsp, client, iid = _setup_factory(ss_node_factory,
                                      funding_sats=200_000)

    out = lsp.rpc.call("factory-list")
    entry = next(f for f in out["factories"]
                 if f["instance_id"] == iid)

    assert entry["is_lsp"] is True
    assert entry["n_clients"] == 1
    assert entry["epoch"] == 0
    assert entry["ceremony"] == "complete"
    # funding_txid must be non-zero after ceremony completion.
    assert entry["funding_txid"] != "0" * 64, (
        f"funding_txid still zero after ceremony complete"
    )
    # max_epochs should be populated (factory-create configured it).
    assert entry["max_epochs"] > 0


def test_factory_force_close_drives_dying_and_registers_cpfps(
        ss_node_factory):
    """After ceremony, factory-force-close should:
      1. Broadcast signed kickoff + state TXs (via ss_broadcast_factory_tx)
      2. Flip lifecycle to DYING
      3. Register pending_cpfp entries (Phase 3c2.5d production wire-up)

    This is the single most valuable E2E test — proves the CPFP path's
    production integration isn't dead code. The ss_find_p2a_vout scanner
    + ss_register_pending_cpfp calls at the DYING cascade broadcast site
    (handle_block_added) + breach_utxo_checked site should fire when
    real tree nodes are broadcast here.

    Accepts both 'dying' and any 'closed_*' lifecycle — once the root
    UTXO is spent and the heartbeat fires, lifecycle may advance past
    DYING via the Phase 3b classifier.

    Note: pyln-testing regtest bitcoind is permissive about relay and
    will accept our kickoff+state TXs even if feerate is unusual. In
    production with congestion, the pending_cpfp entries we register
    here would get their scheduler tick + CPFP child broadcast."""
    import time
    lsp, client, iid = _setup_factory(ss_node_factory)

    # Drive force-close.
    lsp.rpc.call("factory-force-close", {"instance_id": iid})

    # Poll for lifecycle advancement AND pending_cpfps registration.
    # Both should happen within ~30s (kickoff/state TXs broadcast via
    # aux_command + DYING flip is synchronous on the force-close path).
    deadline = time.time() + 30.0
    final_lifecycle = None
    final_n_cpfps = 0
    while time.time() < deadline:
        entry = next(f for f in lsp.rpc.call("factory-list")["factories"]
                     if f["instance_id"] == iid)
        final_lifecycle = entry["lifecycle"]
        final_n_cpfps = len(entry.get("pending_cpfps", []))
        if final_lifecycle != "active" and final_n_cpfps > 0:
            break
        time.sleep(0.5)

    # Lifecycle should have advanced past active. Accept dying or
    # any closed_* — classifier might refine further depending on
    # what bitcoind confirmed.
    assert final_lifecycle in {
        "dying", "closed_externally", "closed_cooperative",
        "closed_unilateral", "expired",
    }, f"force-close didn't advance lifecycle; stuck at {final_lifecycle}"

    # At least one pending_cpfp should have been registered by the
    # production wire-up in Phase 3c2.5d. If zero, the vout scanner
    # didn't find a P2A output OR registration isn't being invoked.
    assert final_n_cpfps > 0, (
        f"force-close broadcast TXs but no pending_cpfps registered. "
        f"Either the tree nodes lack P2A anchors (factory fee config?) "
        f"or Phase 3c2.5d registration isn't firing at this site."
    )


def test_factory_rotate_bumps_epoch(ss_node_factory):
    """After ceremony, factory-rotate advances the epoch counter.
    Validates that the rotation ceremony itself (NONCE re-exchange,
    state TX re-signing) completes end-to-end. Without this, all the
    classifier's per-epoch logic is unreachable in tests."""
    lsp, client, iid = _setup_factory(ss_node_factory)

    # Initial epoch = 0.
    before = next(f for f in lsp.rpc.call("factory-list")["factories"]
                  if f["instance_id"] == iid)
    assert before["epoch"] == 0

    # Drive rotation.
    lsp.rpc.call("factory-rotate", {"instance_id": iid})

    # Poll for epoch bump. The rotation ceremony is async — same
    # custommsg 33001 round-trip as initial.
    import time
    deadline = time.time() + 60.0
    final_epoch = 0
    while time.time() < deadline:
        entry = next(f for f in lsp.rpc.call("factory-list")["factories"]
                     if f["instance_id"] == iid)
        final_epoch = entry["epoch"]
        if final_epoch > 0:
            break
        time.sleep(0.5)

    assert final_epoch == 1, (
        f"rotation didn't bump epoch — stayed at {final_epoch}. Check "
        f"client log for REVOKE + REVOKE_ACK + NONCE_BUNDLE exchange."
    )
