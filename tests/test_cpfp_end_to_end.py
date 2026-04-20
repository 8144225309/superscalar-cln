"""E2E tests for Phase 3c2.5c — full CPFP pipeline.

Chain: ss_build_cpfp_child → ss_cpfp_sign_and_send
                  → reserveinputs → signpsbt → sendpsbt

On success: CPFP child TX is in the mempool, child_txid returned.
On failure: best-effort unreserveinputs + fail reason.

Note: pyln-testing's regtest bitcoind doesn't do package relay by
default — the CPFP child will be relayed on its own if its feerate
clears the mempool minimum. For testing, we're not verifying that the
(non-existent) synthetic parent actually gets pulled in; just that
the child TX itself makes it to the mempool with correct structure.
"""
from __future__ import annotations


def _funded_lsp(ss_node_factory):
    # broken_log regex: our tests use synthetic parent_txid ("aaaa...")
    # which doesn't exist on chain. When reserveinputs runs, CLN tries
    # to validate the input and emits BROKEN "No transaction found for
    # UTXO <txid>". That's expected in these scaffolding tests — the
    # full end-to-end with a real parent is a Phase 5b regtest concern.
    lsp = ss_node_factory.get_node(
        broken_log=r"No transaction found for UTXO"
    )
    lsp.fundwallet(10_000_000)
    return lsp


def test_cpfp_end_to_end_child_broadcasts(ss_node_factory):
    """Full pipeline: build → reserve → sign → send. Returns the
    child txid. Mempool should show it.

    BUT: the child spends a synthetic non-existent parent's anchor.
    bitcoind will reject it with 'missing-inputs'. That failure mode
    is the EXPECTED result for this synthetic test — it proves the
    pipeline assembled a wire-valid TX all the way to sendrawtransaction
    rejection at the final relay step. We accept either 'ok' (if the
    mempool somehow accepts, unlikely) OR 'sendpsbt_failed' (the
    realistic case). Both prove the sign/send plumbing is wired."""
    lsp = _funded_lsp(ss_node_factory)
    r = lsp.rpc.call("dev-factory-test-cpfp-end-to-end", {})

    # Plumbing validity: pipeline MUST advance past the build step.
    # A "fail" with reason indicating wallet/UTXO issue = pipeline
    # broken at 3c2.5a/b layer. A "fail" with sendpsbt_failed = all
    # layers executed, bitcoind rejected at relay (expected here).
    assert r["status"] in {"ok", "fail"}
    if r["status"] == "fail":
        assert r["reason"] in {
            "sendpsbt_failed",
            "sendpsbt_no_txid",
        }, f"unexpected fail reason: {r['reason']!r}"
    else:
        # Real broadcast somehow succeeded.
        assert r["child_txid"]
        assert len(r["child_txid"]) == 64


def test_cpfp_end_to_end_fails_when_wallet_empty(ss_node_factory):
    """No wallet funds → fails at the build step with no_confirmed_utxo
    (propagated from 3c2.5a). Reserve/sign/send never run."""
    lsp = ss_node_factory.get_node()
    r = lsp.rpc.call("dev-factory-test-cpfp-end-to-end", {})
    assert r["status"] == "fail"
    assert r["reason"] in {"no_confirmed_utxo", "wallet_insufficient"}
    # PSBT never built — no "psbt" field in response.
    assert "psbt" not in r


def test_cpfp_end_to_end_low_feerate_path(ss_node_factory):
    """Low target feerate → tiny bump_fee → easy to find a wallet
    UTXO. Exercises the happy build path; the final broadcast may
    still fail at bitcoind because the parent doesn't exist."""
    lsp = _funded_lsp(ss_node_factory)
    r = lsp.rpc.call("dev-factory-test-cpfp-end-to-end", {
        "target_feerate_sat_per_kvb": 2000,
    })
    assert r["status"] in {"ok", "fail"}
    # Either way, we at least got past build — psbt should be set.
    assert "psbt" in r
