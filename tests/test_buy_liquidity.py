"""factory-buy-liquidity arity restriction (matches upstream).

Per /root/SuperScalar/src/lsp_channels.c:1962, upstream's
lsp_channels_buy_liquidity rejects every leaf_arity that isn't
FACTORY_ARITY_2:

    if (f->leaf_arity != FACTORY_ARITY_2) {
        fprintf(stderr, "buy_liquidity: only supported for arity-2\n");
        return 0;
    }

The plugin previously allowed buy-liquidity on ARITY_PS chain[0] (and
implicitly ARITY_1) — design-divergent from upstream. ARITY_PS leaves
have no chain-level invalidation for a chain[0] re-sign (TX chaining
needs a unique parent_txid+vout, which a re-sign violates), and ARITY_1
is a degenerate 1-client case upstream simply doesn't implement.

These tests pin the new behavior: the RPC rejects ARITY_PS and ARITY_1
factories with a clear error pointing at factory rotation as the
recovery path. The ARITY_2 happy-path test lives at signet level until
a 3-node ceremony helper exists in pyln-testing.
"""
from __future__ import annotations

import pytest
from pyln.client import RpcError

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)


def _setup_factory(ss_node_factory, arity_mode="arity_ps",
                   funding_sats=500_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def test_buy_liquidity_rejects_arity_ps(ss_node_factory):
    """ARITY_PS factories should refuse buy-liquidity — TX chaining
    cannot invalidate a chain[0] re-sign because both old and new
    chain[0] would spend the same parent UTXO with the same nSequence."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    with pytest.raises(RpcError, match="only supported on ARITY_2"):
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 10_000,
        })


def test_buy_liquidity_rejects_arity_1(ss_node_factory):
    """ARITY_1 (single-client per leaf, 2-of-2 DW) is also rejected by
    upstream — "buying liquidity from yourself" on a leaf with one client
    is degenerate. Operators wanting more inbound on an ARITY_1 leaf
    should rotate the factory with new initial amounts."""
    lsp, _client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_1")

    with pytest.raises(RpcError, match="only supported on ARITY_2"):
        lsp.rpc.call("factory-buy-liquidity", {
            "instance_id": iid,
            "client_idx": 0,
            "amount_sats": 10_000,
        })


# ARITY_2 happy-path verification lives at signet level — the upstream
# tree builder rejects a 1-client+arity_2 factory before the RPC can
# fire, and pyln-testing has no 3-node ceremony helper. The signet
# evidence is recorded in the conversation around tasks #98/#99/#100,
# end-to-end metrics:
#   LSP:         realloc_propose → nonce_recv ×2 → all_nonces_sent →
#                psig3_recv ×2 → realloc_complete
#   each client: nonce_sent → all_nonces_recv → psig3_sent → client_done
