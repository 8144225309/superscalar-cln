"""Regression for the client-side load-path crash.

ss_load_factories used to hard-code slot=0 for every fi->clients[ci]
entry on the non-LSP path, which worked by coincidence for 2-party
factories (one entry, slot 0 is LSP) but corrupted pks[0] and left
peer slots zeroed for any 3+-party factory. Plugin restart on a node
that had ever participated in an ARITY_2 (3-of-3) ceremony then
crashed inside secp256k1_musig_pubkey_agg.

The fix stores each peer's pubkey + signer_slot at FACTORY_PROPOSE
time and reads signer_slot in the load loop. End-to-end verification
for the 3-party case lives on signet (no 3-node test helper exists
yet — see the deferred ARITY_2 test in test_buy_liquidity.py); this
test guards the 2-party path against regressions in the new
FACTORY_PROPOSE bookkeeping and the load-loop refactor.
"""
from __future__ import annotations

from conftest import create_two_party_factory, wait_for_ceremony_complete


def test_client_plugin_reloads_factory_after_restart(ss_node_factory):
    """Create a 2-party factory, restart the CLIENT, confirm the
    plugin boots cleanly and factory-list still reports the factory
    with the same instance_id."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)

    iid = create_two_party_factory(lsp, client,
                                   funding_sats=200_000,
                                   timeout=60.0,
                                   arity_mode="arity_ps")
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    # Wait for the CLIENT side ceremony to also reach 'complete'.
    # wait_for_ceremony_complete polls the LSP — the client side
    # ceremony state machine lags slightly because it advances on
    # FACTORY_READY receipt. Without this wait, the test races and
    # may catch the client at 'nonces_collected' or 'psigs_collected'.
    import time
    deadline = time.time() + 60.0
    pre = None
    while time.time() < deadline:
        f = next(x for x in client.rpc.call("factory-list")["factories"]
                 if x["instance_id"] == iid)
        if f["ceremony"] == "complete":
            pre = f
            break
        time.sleep(0.5)
    assert pre is not None and pre["ceremony"] == "complete", (
        "client side ceremony didn't reach 'complete' within 60s")

    # Restart triggers ss_load_factories on the client side.
    # Pre-fix this would have crashed with SIGABRT inside
    # secp256k1_musig_pubkey_agg for any factory with >2 signers;
    # for 2-party it works but the load-loop change still has to
    # be exercised end-to-end.
    client.restart()

    post = next(f for f in client.rpc.call("factory-list")["factories"]
                if f["instance_id"] == iid)
    assert post["instance_id"] == pre["instance_id"]
    assert post["ceremony"] == pre["ceremony"]
    assert post["arity_mode"] == pre["arity_mode"]
    assert post["n_clients"] == pre["n_clients"]
