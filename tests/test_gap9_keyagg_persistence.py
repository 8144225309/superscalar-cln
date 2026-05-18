"""GAPS Gap 9 — MuSig2 keyagg cache persistence.

Verifies that the keyagg cache snapshot blob is captured at sign-time
builds, persisted in meta v15, and restored byte-identically after an
LSP restart. Defends the signet-recovery scenario where a recomputed
cache produced sigs that failed on-chain validation despite the x-only
agg pubkey matching.

Surface:
  - dev-superscalar-state exposes keyagg_snapshots_len + a SHA256
    fingerprint of the blob.
  - After ceremony complete, the blob is non-empty.
  - After lsp.restart(), the fingerprint is byte-identical.
"""
from __future__ import annotations

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)


def _state(lsp, iid):
    return lsp.rpc.call("dev-superscalar-state", {"instance_id": iid})


def test_keyagg_snapshot_captured_after_ceremony(ss_node_factory):
    """A 2-party factory's keyagg snapshot blob is non-empty after the
    LSP runs through factory-create → continue_after_funding."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client, funding_sats=200_000)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    s = _state(lsp, iid)
    assert s["keyagg_snapshots_len"] > 0, (
        "expected non-empty keyagg snapshot blob after ceremony — "
        "ss_keyagg_snapshot_capture didn't fire on the LSP rebuild")
    assert s["keyagg_snapshots_fingerprint"], (
        "snapshot blob present but fingerprint empty — dev RPC bug")
    assert len(s["keyagg_snapshots_fingerprint"]) == 64


def test_keyagg_snapshot_survives_lsp_restart(ss_node_factory):
    """The persisted keyagg blob round-trips through meta v15 — the
    fingerprint after lsp.restart() must equal the pre-restart one,
    proving ss_keyagg_snapshot_restore loaded the same bytes."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client, funding_sats=200_000)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    pre = _state(lsp, iid)
    pre_fp = pre["keyagg_snapshots_fingerprint"]
    pre_len = pre["keyagg_snapshots_len"]
    assert pre_fp, "no snapshot captured before restart"

    lsp.restart()

    post = _state(lsp, iid)
    assert post["keyagg_snapshots_len"] == pre_len, (
        f"blob length changed across restart: pre={pre_len} "
        f"post={post['keyagg_snapshots_len']} — meta v15 round-trip broken")
    assert post["keyagg_snapshots_fingerprint"] == pre_fp, (
        f"keyagg blob fingerprint diverged across restart:\n"
        f"  pre  = {pre_fp}\n"
        f"  post = {post['keyagg_snapshots_fingerprint']}\n"
        "either persist v15 isn't writing the blob or "
        "ss_keyagg_snapshot_restore isn't reading it")


def test_keyagg_snapshot_survives_client_restart(ss_node_factory):
    """The client side also captures + persists keyagg blobs (PROPOSE
    and ALL_NONCES rebuilds). Ensure those round-trip too."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client, funding_sats=200_000)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    # Client also needs to have its ceremony complete before its blob
    # is meaningful.
    wait_for_ceremony_complete(client, iid, timeout=120.0)

    pre = _state(client, iid)
    pre_fp = pre["keyagg_snapshots_fingerprint"]
    pre_len = pre["keyagg_snapshots_len"]
    assert pre_fp, "client did not capture keyagg snapshot"

    client.restart()

    post = _state(client, iid)
    assert post["keyagg_snapshots_len"] == pre_len, (
        f"client blob length changed across restart: pre={pre_len} "
        f"post={post['keyagg_snapshots_len']}")
    assert post["keyagg_snapshots_fingerprint"] == pre_fp, (
        "client keyagg fingerprint diverged across restart")
