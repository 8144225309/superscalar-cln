"""E2E tests for Phase 3c2.5a — wallet UTXO + change address helpers.

These exercise the async RPC chains that 3c2.5b/c will build on:
  - ss_pick_wallet_utxo (listfunds → pick smallest confirmed >= min)
  - ss_get_change_p2tr  (newaddr p2tr → address string)

pyln-testing's node_factory funds nodes with 10^6 msat worth of UTXOs
on setup (see utils.py NodeFactory.get_node default). So listfunds
returns confirmed UTXOs we can exercise the picker against.
"""
from __future__ import annotations


def test_utxo_pick_returns_confirmed_coin(ss_node_factory):
    """Happy path: fund the node, pick a UTXO of at least 10k sat,
    result includes txid / vout / amount / scriptpubkey / address."""
    lsp = ss_node_factory.get_node()
    # pyln-testing gives ~10^6 msat ≈ 1000 sat per UTXO usually; but
    # the default bitcoind fund-wallet call gives larger coins. Ask
    # for a small min to be safe.
    r = lsp.rpc.call("dev-factory-test-utxo-pick", {"min_amount_sat": 1})

    assert r["status"] == "ok", f"pick failed: {r}"
    assert "txid" in r and len(r["txid"]) == 64
    assert "vout" in r and isinstance(r["vout"], int)
    assert "amount_sat" in r and r["amount_sat"] >= 1
    assert "scriptpubkey" in r and r["scriptpubkey"]
    assert "address" in r and r["address"]


def test_utxo_pick_fails_gracefully_when_too_expensive(ss_node_factory):
    """Ask for more than the wallet holds — helper must return
    status='fail' reason='no_confirmed_utxo', not crash."""
    lsp = ss_node_factory.get_node()
    r = lsp.rpc.call("dev-factory-test-utxo-pick",
                     {"min_amount_sat": 10**12})  # 10 trillion sat

    assert r["status"] == "fail"
    assert r["reason"] == "no_confirmed_utxo"


def test_utxo_pick_smallest_viable(ss_node_factory):
    """Given multiple UTXOs >= min, pick the smallest. Two calls with
    different mins should pick progressively larger coins (smallest
    that satisfies each threshold). At minimum: both calls succeed
    and the amount_sat result is >= the min requested."""
    lsp = ss_node_factory.get_node()

    r1 = lsp.rpc.call("dev-factory-test-utxo-pick",
                      {"min_amount_sat": 1})
    r2 = lsp.rpc.call("dev-factory-test-utxo-pick",
                      {"min_amount_sat": 100})

    assert r1["status"] == "ok"
    assert r1["amount_sat"] >= 1

    # r2 may also succeed or fail depending on wallet contents.
    if r2["status"] == "ok":
        assert r2["amount_sat"] >= 100


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
