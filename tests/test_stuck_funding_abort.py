"""E2E tests for Phase 4c — stuck-funding abort.

Operational gap: factories whose ceremony stalls indefinitely (counterparty
never responds) accumulate in INIT lifecycle, polluting watcher state and
hiding from operator visibility. The 5 zombies on cln-blip56 motivated
this phase.

Phase 4c adds:
  - FACTORY_LIFECYCLE_ABORTED (= 8) — terminal, factory_is_closed() true
  - aborted_at_block — forensic timestamp
  - factory-abort-stuck operator RPC — flips INIT → ABORTED
  - blocks_in_init in factory-list — visibility
  - auto-warning on block_added when an INIT factory has been stuck
    > FACTORY_INIT_STUCK_BLOCKS (default 144 ~1 day at 10-min blocks)
"""
from __future__ import annotations

FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def _factory(lsp, iid: str) -> dict:
    out = lsp.rpc.call("factory-list")
    for f in out["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not in factory-list")


def test_abort_stuck_flips_init_to_aborted(ss_node_factory):
    """Happy path: stalled INIT factory → factory-abort-stuck →
    lifecycle=aborted, aborted_at_block populated, response surfaces
    has_on_chain_funding=false (no funding for fake-peer factories)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    fs_before = _factory(lsp, iid)
    assert fs_before["lifecycle"] == "init"

    r = lsp.rpc.call("factory-abort-stuck", {"instance_id": iid})
    assert r["lifecycle"] == "aborted"
    assert r["previous_lifecycle"] == "init"
    assert r["has_on_chain_funding"] is False
    assert "recovery_path" not in r  # no recovery needed without funding

    fs_after = _factory(lsp, iid)
    assert fs_after["lifecycle"] == "aborted"
    assert "aborted_at_block" in fs_after


def test_abort_stuck_refuses_non_init_without_force(ss_node_factory):
    """Operator must explicitly force=true to abort a non-INIT factory.
    Guards against accidentally clobbering an active or closed
    lifecycle (which carry more-specific labels already)."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Force factory to closed_cooperative via Phase 3b dist signal.
    lsp.rpc.call("dev-factory-set-signal",
                 {"instance_id": iid, "signal": "dist_txid_matched"})
    fs = _factory(lsp, iid)
    assert fs["lifecycle"] == "closed_cooperative"

    # Should fail without force.
    try:
        lsp.rpc.call("factory-abort-stuck", {"instance_id": iid})
        raise AssertionError("expected RPC error without force=true")
    except Exception as e:
        assert "force" in str(e).lower() or "init" in str(e).lower()

    # Should succeed with force.
    r = lsp.rpc.call("factory-abort-stuck",
                     {"instance_id": iid, "force": True})
    assert r["lifecycle"] == "aborted"


def test_factory_list_renders_blocks_in_init(ss_node_factory):
    """factory-list surfaces blocks_in_init for INIT factories so
    operators can spot stuck ceremonies. Not present for non-INIT."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    fs = _factory(lsp, iid)
    assert fs["lifecycle"] == "init"
    # blocks_in_init may be 0 (just created in same block as fixture)
    # or > 0 if a few blocks elapsed during test setup. Either is fine
    # — the field MUST be present for INIT factories.
    assert "blocks_in_init" in fs

    # After abort, blocks_in_init must NOT appear (we're no longer in
    # INIT).
    lsp.rpc.call("factory-abort-stuck", {"instance_id": iid})
    fs2 = _factory(lsp, iid)
    assert fs2["lifecycle"] == "aborted"
    assert "blocks_in_init" not in fs2


def test_aborted_factory_skipped_by_breach_scan(ss_node_factory):
    """factory_is_closed(ABORTED) must return true so the breach scan
    in handle_block_added skips ABORTED factories. Asserted indirectly:
    after abort, dev-factory-set-signal still works (not gated by
    closed status), but the scan-eligible state is closed."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    lsp.rpc.call("factory-abort-stuck", {"instance_id": iid})

    fs = _factory(lsp, iid)
    assert fs["lifecycle"] == "aborted"
    # apply_signals' can_refine check rejects further transitions for
    # closed lifecycles other than CLOSED_EXTERNALLY. ABORTED is in the
    # closed set, so injecting utxo_spent should NOT downgrade.
    lsp.rpc.call("dev-factory-set-signal",
                 {"instance_id": iid, "signal": "utxo_spent"})
    fs2 = _factory(lsp, iid)
    assert fs2["lifecycle"] == "aborted", (
        "ABORTED downgraded by utxo_spent — closed-set membership "
        "not honored"
    )


def test_abort_stuck_idempotent_with_force(ss_node_factory):
    """Aborting an already-aborted factory with force=true is a
    no-op-ish: lifecycle stays aborted, aborted_at_block updates to
    current. Operator using force on an already-aborted record
    shouldn't crash."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)
    lsp.rpc.call("factory-abort-stuck", {"instance_id": iid})
    r = lsp.rpc.call("factory-abort-stuck",
                     {"instance_id": iid, "force": True})
    assert r["lifecycle"] == "aborted"
