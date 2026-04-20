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
