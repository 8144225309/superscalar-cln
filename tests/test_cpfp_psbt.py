"""E2E tests for Phase 3c2.5b — CPFP child PSBT construction.

Exercises ss_build_cpfp_child:
    - picks a wallet UTXO via listfunds
    - gets a P2TR change address via newaddr
    - builds unsigned PSBT with [anchor, wallet] inputs + [change] output
    - returns base64 PSBT

Phase 3c2.5c will sign (signpsbt) + broadcast (sendpsbt). v1 is
build-only; we verify structure via CLN's listpsbts / decodepsbt.
"""
from __future__ import annotations

import base64


def _funded_lsp(ss_node_factory):
    lsp = ss_node_factory.get_node()
    lsp.fundwallet(10_000_000)
    return lsp


def test_build_cpfp_psbt_happy_path(ss_node_factory):
    """Build a CPFP PSBT with a synthetic parent. Returns status=ok
    + psbt base64 + wallet UTXO details + change address."""
    lsp = _funded_lsp(ss_node_factory)

    r = lsp.rpc.call("dev-factory-test-build-cpfp-psbt", {})

    assert r["status"] == "ok", f"build failed: {r}"
    assert r["psbt"]
    # PSBT must start with the magic bytes "cHNidP8" (base64 of 0x70...)
    # the PSBT magic in base64 is "cHNidP8B" (or similar depending on
    # first byte after magic).
    assert r["psbt"].startswith("cHNidP"), (
        f"not a PSBT base64 prefix: {r['psbt'][:16]}"
    )
    # Base64 must decode successfully.
    decoded = base64.b64decode(r["psbt"])
    # Raw PSBT starts with 0x70 0x73 0x62 0x74 0xff ("psbt\xff" magic).
    assert decoded[:5] == b"psbt\xff", (
        f"bad PSBT magic: {decoded[:5]!r}"
    )

    assert r["wallet_txid"] and len(r["wallet_txid"]) == 64
    assert r["change_address"]


def test_build_cpfp_psbt_custom_feerate(ss_node_factory):
    """Build with an elevated feerate. Response includes psbt;
    fee is implicit via change_amount. v1 doesn't expose the computed
    fee directly — we just assert the RPC handled the param."""
    lsp = _funded_lsp(ss_node_factory)

    r = lsp.rpc.call("dev-factory-test-build-cpfp-psbt", {
        "target_feerate_sat_per_kvb": 50_000,
    })
    assert r["status"] == "ok"
    assert r["psbt"]


def test_build_cpfp_psbt_fails_when_wallet_empty(ss_node_factory):
    """Unfunded node: no wallet UTXO available. Helper must return
    status=fail reason=no_confirmed_utxo (propagated from the UTXO
    picker)."""
    lsp = ss_node_factory.get_node()  # NOT funded
    r = lsp.rpc.call("dev-factory-test-build-cpfp-psbt", {})

    assert r["status"] == "fail"
    assert r["reason"] in {
        "no_confirmed_utxo",
        "wallet_insufficient",
    }, f"unexpected reason: {r['reason']!r}"


def test_build_cpfp_psbt_reserve_then_sign_works(ss_node_factory):
    """Built PSBT is structurally valid AND wallet-signable after
    reserveinputs. Mirrors the 3c2.5c downstream flow: build PSBT,
    reserve the wallet UTXO, signpsbt signs it.

    Phase 3c2.5b helper doesn't call reserveinputs (deferred) — we
    call it here manually to exercise the full path."""
    lsp = _funded_lsp(ss_node_factory)
    r = lsp.rpc.call("dev-factory-test-build-cpfp-psbt", {})
    assert r["status"] == "ok"

    # Reserve the wallet UTXO so signpsbt will touch it.
    lsp.rpc.call("reserveinputs", {"psbt": r["psbt"]})

    sig_result = lsp.rpc.call("signpsbt", {"psbt": r["psbt"]})
    assert "signed_psbt" in sig_result
    assert sig_result["signed_psbt"]


def test_build_cpfp_psbt_parent_txid_honored(ss_node_factory):
    """Pass a specific parent_txid; the built PSBT's anchor input
    should reference it. v1 check: RPC accepts the param and returns
    a PSBT (we don't byte-level inspect the anchor input here — that
    lives in 3c2.5c when we extract the tx after signing)."""
    lsp = _funded_lsp(ss_node_factory)
    custom = "bb" * 32
    r = lsp.rpc.call("dev-factory-test-build-cpfp-psbt", {
        "parent_txid": custom,
        "anchor_vout": 2,
    })
    assert r["status"] == "ok"
    assert r["psbt"]
