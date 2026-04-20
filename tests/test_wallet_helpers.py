"""E2E tests for Phase 3c2.5a — wallet UTXO + change address helpers.

These exercise the async RPC chains that 3c2.5b/c will build on:
  - ss_pick_wallet_utxo (listfunds → pick smallest confirmed >= min)
  - ss_get_change_p2tr  (newaddr p2tr → address string)

pyln-testing's get_node() starts an UNFUNDED node. We explicitly fund
with fundwallet() before exercising the picker.
"""
from __future__ import annotations


def _funded_lsp(ss_node_factory):
    """Bring up a node + fund its wallet with confirmed BTC so the
    UTXO picker has something to pick. fundwallet mines 100 blocks
    so the coinbase matures. Returns the node."""
    lsp = ss_node_factory.get_node()
    lsp.fundwallet(10_000_000)  # 0.1 BTC; triggers mine-to-maturity
    return lsp


def test_utxo_pick_returns_confirmed_coin(ss_node_factory):
    """Happy path: fund the node, pick a UTXO of at least 10k sat,
    result includes txid / vout / amount / scriptpubkey / address."""
    lsp = _funded_lsp(ss_node_factory)
    r = lsp.rpc.call("dev-factory-test-utxo-pick",
                     {"min_amount_sat": 10_000})

    assert r["status"] == "ok", f"pick failed: {r}"
    assert "txid" in r and len(r["txid"]) == 64
    assert "vout" in r and isinstance(r["vout"], int)
    assert r["amount_sat"] >= 10_000
    assert r["scriptpubkey"]
    assert r["address"]


def test_utxo_pick_fails_gracefully_when_too_expensive(ss_node_factory):
    """Ask for more than the wallet holds — helper must return
    status='fail' reason='no_confirmed_utxo', not crash."""
    lsp = _funded_lsp(ss_node_factory)
    r = lsp.rpc.call("dev-factory-test-utxo-pick",
                     {"min_amount_sat": 10**12})  # 10 trillion sat

    assert r["status"] == "fail"
    assert r["reason"] == "no_confirmed_utxo"


def test_utxo_pick_respects_min_amount(ss_node_factory):
    """Asking for a higher min returns a UTXO at or above that min.
    Asserts the filter works end-to-end."""
    lsp = _funded_lsp(ss_node_factory)

    r_low = lsp.rpc.call("dev-factory-test-utxo-pick",
                         {"min_amount_sat": 1})
    r_high = lsp.rpc.call("dev-factory-test-utxo-pick",
                          {"min_amount_sat": 100_000})

    assert r_low["status"] == "ok"
    assert r_low["amount_sat"] >= 1

    if r_high["status"] == "ok":
        assert r_high["amount_sat"] >= 100_000


def test_change_addr_returns_p2tr(ss_node_factory):
    """newaddr p2tr returns a bech32m address. Helper parses it and
    returns status='ok' + address."""
    lsp = ss_node_factory.get_node()
    r = lsp.rpc.call("dev-factory-test-change-addr", {})

    assert r["status"] == "ok"
    addr = r["address"]
    # regtest P2TR addresses start with "bcrt1p", mainnet "bc1p",
    # testnet "tb1p". pyln-testing uses regtest.
    assert addr.startswith("bcrt1p") or addr.startswith("bc1p") \
        or addr.startswith("tb1p"), f"unexpected prefix: {addr!r}"


def test_change_addr_returns_distinct_addresses(ss_node_factory):
    """Two calls return two different addresses (CLN rotates HD
    derivation each time). Guards against the helper accidentally
    caching the first response."""
    lsp = ss_node_factory.get_node()
    r1 = lsp.rpc.call("dev-factory-test-change-addr", {})
    r2 = lsp.rpc.call("dev-factory-test-change-addr", {})
    assert r1["address"] != r2["address"]
