"""E2E signal-path tests for the Phase 3b classifier.

These exercise ``ss_apply_signals`` end-to-end through the plugin RPC
surface using the ``dev-factory-set-signal`` injection hook. Each test
drives one signal (or combination) and asserts the resulting lifecycle
— which is the actual contract the classifier promises to downstream
consumers of ``factory-list``.

Why injection instead of a real on-chain ceremony:
    A full regtest ceremony requires factory-create → NONCE exchange →
    factory-open-channels + channel fundchannel negotiation + mining.
    Channel-open automation from pytest is not yet solved (see
    tests/signet/smoke_basic.sh for the manual signet path). The
    classifier itself is the unit of logic we care about here; injecting
    signals directly tests every branch without paying the ceremony
    tax. A Phase 5b PR can add ceremony-driven tests on top of whatever
    channel-open automation lands upstream.

Coverage map (one test per classifier branch in ss_apply_signals):
    utxo_spent alone              → closed_externally
    broadcast_known alone         → closed_unilateral
    witness_current_match alone   → closed_unilateral
    state_tx_match (current epoch)→ closed_unilateral
    state_tx_match (past epoch)   → closed_breached  (breach_epoch set)
    witness_past_match            → closed_breached
    dist_txid_matched             → closed_cooperative  (outranks others)
    idempotence                   → re-applying same signal is a no-op
    no-downgrade                  → CLOSED_COOPERATIVE stays even if
                                    UTXO_SPENT is set afterwards
"""
from __future__ import annotations

import pytest


# Fake client node_id so factory-create doesn't need a real peer. The
# factory stalls at NONCE exchange but the record exists — which is all
# we need for signal injection.
FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    """Create a factory on ``lsp`` with a fake client peer. Returns the
    instance_id. Ceremony will never complete (no real peer) but the
    factory record persists, which is enough for signal injection."""
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def _inject(lsp, iid: str, signal: str, match_epoch: int | None = None):
    """Wrapper around dev-factory-set-signal. Returns the RPC response."""
    params = {"instance_id": iid, "signal": signal}
    if match_epoch is not None:
        params["match_epoch"] = match_epoch
    return lsp.rpc.call("dev-factory-set-signal", params)


def _factory_state(lsp, iid: str) -> dict:
    """Return the factory record from factory-list for assertions."""
    out = lsp.rpc.call("factory-list")
    for f in out["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not in factory-list")


def test_utxo_spent_alone_flips_to_closed_externally(ss_node_factory):
    """Heartbeat observes root spent with no other corroborating signal.
    The safest labeling is CLOSED_EXTERNALLY — we know it's closed but
    can't attribute it yet."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "utxo_spent")
    assert r["lifecycle"] == "closed_externally"

    fs = _factory_state(lsp, iid)
    assert fs["lifecycle"] == "closed_externally"
    assert "utxo_spent" in fs["signals"]


def test_broadcast_known_alone_flips_to_closed_unilateral(ss_node_factory):
    """Our own kickoff broadcast got '-27: already in utxo set' back.
    Someone else got there first: peer published a kickoff. With no
    finer signal we label CLOSED_UNILATERAL with epoch unknown."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "broadcast_known")
    assert r["lifecycle"] == "closed_unilateral"


def test_witness_current_match_flips_to_closed_unilateral(ss_node_factory):
    """Phase 2b: witness sig on the spending TX matches the CURRENT
    epoch. Counterparty force-closed at the latest state — not a
    breach, just an uncoordinated exit."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "witness_current_match")
    assert r["lifecycle"] == "closed_unilateral"


def test_state_tx_match_current_epoch_is_unilateral(ss_node_factory):
    """Phase 3b: downstream scan found a state TX spending the
    kickoff's output, and its txid matches the cached state-root TXID
    for the current epoch. Normal exit."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Factory is at epoch 0 since ceremony stalled. match_epoch=0 means
    # "current" for this fixture.
    r = _inject(lsp, iid, "state_tx_match", match_epoch=0)
    assert r["lifecycle"] == "closed_unilateral"


def test_state_tx_match_non_current_epoch_is_breached(ss_node_factory):
    """Phase 3b: downstream scan found a state TX whose epoch does NOT
    match the factory's current epoch. Classifier treats any epoch
    mismatch (not strictly 'past') as breach — the factory has already
    rotated past whatever state this TX belongs to, so publishing it
    is a revoked-state attack. breach_epoch gets populated with the
    mismatched epoch for the downstream penalty path.

    We can't advance fi->epoch without a full ceremony + rotation, but
    the classifier only cares about !=, so injecting match_epoch=5 on
    a factory stuck at epoch=0 exercises the same code path."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "state_tx_match", match_epoch=5)
    assert r["lifecycle"] == "closed_breached"

    fs = _factory_state(lsp, iid)
    assert fs["breach_epoch"] == 5
    assert "state_tx_match" in fs["signals"]
    assert fs["state_tx_match_epoch"] == 5


def test_witness_past_match_is_breached(ss_node_factory):
    """Strongest breach signal: witness sig on the spending TX matched a
    PAST epoch's saved witness. Classifier should flip to
    closed_breached with breach_epoch populated."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "witness_past_match", match_epoch=7)
    assert r["lifecycle"] == "closed_breached"

    fs = _factory_state(lsp, iid)
    assert fs["breach_epoch"] == 7
    assert "witness_past_match" in fs["signals"]


def test_dist_txid_matched_is_cooperative(ss_node_factory):
    """Phase 2b: spending TX matched our cached dist_signed_txid. That's
    a cooperative close — we knew about this TX and it executed."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r = _inject(lsp, iid, "dist_txid_matched")
    assert r["lifecycle"] == "closed_cooperative"


def test_signal_set_is_idempotent(ss_node_factory):
    """Re-injecting the same signal twice should not change the state
    beyond the first injection. Tests the 'signal-arrival order
    independence' invariant of ss_apply_signals."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r1 = _inject(lsp, iid, "utxo_spent")
    r2 = _inject(lsp, iid, "utxo_spent")
    assert r1["lifecycle"] == r2["lifecycle"] == "closed_externally"
    assert r1["signals_observed"] == r2["signals_observed"]


def test_cooperative_does_not_downgrade_to_external(ss_node_factory):
    """Classifier can refine CLOSED_EXTERNALLY → better label, but must
    NEVER move backwards: once we've identified a cooperative close,
    seeing a UTXO_SPENT signal afterwards (a weaker evidence source)
    must not reset the label to 'externally closed' ambiguity."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    r1 = _inject(lsp, iid, "dist_txid_matched")
    assert r1["lifecycle"] == "closed_cooperative"

    r2 = _inject(lsp, iid, "utxo_spent")
    assert r2["lifecycle"] == "closed_cooperative", (
        "classifier downgraded from cooperative to externally-closed — "
        "no-downgrade invariant broken"
    )


def test_factory_list_renders_phase3b_fields(ss_node_factory):
    """Regression: the factory-list output must render the new Phase 3b
    fields (signals_observed bitmask + decoded signals array +
    state_tx_match_epoch) when populated, and must NOT render them on a
    fresh factory with no signals fired."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    # Before injection: none of the new fields should appear.
    fs_before = _factory_state(lsp, iid)
    assert "signals_observed" not in fs_before
    assert "signals" not in fs_before
    assert "state_tx_match_epoch" not in fs_before

    _inject(lsp, iid, "utxo_spent")
    _inject(lsp, iid, "broadcast_known")

    fs_after = _factory_state(lsp, iid)
    assert fs_after["signals_observed"] > 0
    assert set(fs_after["signals"]) == {"utxo_spent", "broadcast_known"}
