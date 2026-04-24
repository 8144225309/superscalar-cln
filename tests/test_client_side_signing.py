"""Follow-up #1 sub-PR 3A — client-side full tree signing.

Before this change, `musig_aggregate_partial_sigs` was never called in the
plugin; clients only sent their partial sigs to the LSP and never received
LSP's sigs back — so their factory_t was never locally signed, their
signed_txs datastore blob was empty, and client-initiated factory-force-
close had nothing to broadcast.

FACTORY_READY (and the DIST_READY / ROTATE_COMPLETE variants in sub-PRs
3B/3C) now carries the LSP's signed tree TXs as a backward-compatible
trailer after the 32-byte instance_id. Clients parse it, populate their
own factory_t, and persist via the existing ss_save_factory path.

This gives clients trustless unilateral exit for the first time.
"""
from __future__ import annotations

import time

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
    datastore_has,
)


def _setup_factory(ss_node_factory, arity_mode=None, funding_sats=100_000):
    """Two plugin-loaded nodes, ceremony driven to completion."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode=arity_mode)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def _datastore_get_raw(node, key_path):
    """Return (hex, True) if the datastore key exists with non-empty value,
    else (None, False)."""
    try:
        r = node.rpc.call("listdatastore", {"key": key_path})
        entries = r.get("datastore", [])
        if entries and entries[0].get("hex"):
            return entries[0]["hex"], True
    except Exception:
        pass
    return None, False


def test_client_persists_signed_tree(ss_node_factory):
    """After ceremony, the CLIENT's datastore should contain a non-empty
    signed_txs blob. Before sub-PR 3A this was empty (LSP never shared
    their signed tree with the client)."""
    _lsp, client, iid = _setup_factory(ss_node_factory)

    # Signed tree blob lives at superscalar/factories/{iid}/signed_txs.
    # Give it a moment to flush (ss_save_factory runs after FACTORY_READY).
    key = ["superscalar", "factories", iid, "signed_txs"]
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if datastore_has(client, key, timeout=0.5):
            break
        time.sleep(0.3)
    assert datastore_has(client, key, timeout=5.0), (
        f"client datastore key {'/'.join(key)} missing — sub-PR 3A trailer "
        "likely not being parsed or the client is running legacy code"
    )

    # Also assert non-empty: a zero-length blob means ss_persist_serialize_
    # signed_txs had no signed nodes — which would mean the client applied
    # nothing. Legacy pre-3A behavior.
    hex_val, ok = _datastore_get_raw(client,
                                     "/".join(str(x) for x in key))
    # pyln datastore returns / joined; listdatastore expects same
    # Actually listdatastore takes `key` as array (per docs). Try that:
    r = client.rpc.call("listdatastore", {"key": key})
    entries = r.get("datastore", [])
    assert entries, "listdatastore returned no entries"
    hex_val = entries[0].get("hex", "")
    # Minimum: u16 count = at least 1 signed node means >= 2 bytes and
    # count > 0. For a 2-party factory with arity_2 default (depth 1 tree)
    # we expect kickoff + state = 2 signed nodes minimum.
    assert len(hex_val) > 4, (
        f"client signed_txs blob too small ({len(hex_val)//2} bytes) — "
        "expected non-empty with at least one signed node"
    )


def test_client_ps_chain0_persisted(ss_node_factory):
    """For an arity_mode=arity_ps factory, once the client has signed tree
    TXs, chain[0] of each PS leaf should also be persisted (via
    ss_save_all_ps_chain0 which runs at FACTORY_READY receive). Before
    sub-PR 3A the client had no signed chain[0] so this entry was
    always absent."""
    _lsp, client, iid = _setup_factory(ss_node_factory,
                                       arity_mode="arity_ps")

    # After ceremony, client should have a ps_chain/{leaf}/0 entry.
    key = ["superscalar", "factories", iid, "ps_chain"]
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if datastore_has(client, key, timeout=0.5):
            break
        time.sleep(0.3)
    assert datastore_has(client, key, timeout=5.0), (
        f"client datastore key {'/'.join(key)} missing — client-side "
        "chain[0] persistence didn't fire. Check that "
        "ss_save_all_ps_chain0 runs in the FACTORY_READY client-side "
        "handler AFTER the signed-tree trailer is applied."
    )


def test_client_force_close_has_signed_txs_loaded(ss_node_factory):
    """After ceremony the CLIENT can call factory-force-close and the plugin
    should attempt to broadcast (even if bitcoind rejects the synthetic
    TXs — what matters is the plugin logs the broadcasts, proving it has
    signed tree TXs in its factory_t).

    Before sub-PR 3A, the client's factory_t had no signed TXs and the
    force-close loop would log 'node X not signed, skipping' for every
    node. After 3A, the client should log actual broadcast attempts."""
    _lsp, client, iid = _setup_factory(ss_node_factory)

    client.rpc.call("factory-force-close", {"instance_id": iid})

    # The force-close loop in superscalar.c logs "force-close: node %zu ..."
    # per broadcast attempt. We don't care if the broadcast ITSELF succeeds
    # (regtest may reject the unconfirmed tree TX chain); we only care
    # that the loop found signed TXs to attempt.
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if client.daemon.is_in_log(r"force-close: node \d+"):
            return
        time.sleep(0.3)
    # If we got here, the client had zero signed nodes to broadcast.
    assert False, (
        "client force-close never logged a broadcast attempt — "
        "no signed tree TXs on the client side. sub-PR 3A did not take "
        "effect (legacy FACTORY_READY behavior)."
    )
