"""Deterministic instance_id from HSM (GAPS.md Gap 8).

Before: iid was 32 bytes of random(). If the datastore was wiped
after a factory was funded on-chain, the iid was irrecoverable —
meaning the master-key + HSM were useless for reconstructing
participant pubkeys, leaf scripts, revocation secrets, etc.

After: iid = SHA256(master_key || "ss-iid-v1" || block_le4 ||
counter_le4). Counter is persisted under "superscalar/iid_counter"
and increments on every factory-create. Datastore-loss recovery is
still possible by enumerating counter values against on-chain
funding addresses, assuming the master key (HSM seed) survives.

These tests verify:
  1. Counter increments across factory-creates.
  2. Counter persists through restarts.
  3. Two rapid-fire factory-creates in the same block produce
     distinct iids (counter breaks the tie).
"""
from __future__ import annotations

FAKE_CLIENT_ID = "02" + "00" * 32
FAKE_CLIENT_ID_2 = "03" + "00" * 32


def _counter_blob(lsp) -> bytes:
    """Read the superscalar/iid_counter datastore entry. Returns
    empty bytes if absent."""
    r = lsp.rpc.call("listdatastore", {"key": ["superscalar",
                                                "iid_counter"]})
    entries = r.get("datastore", [])
    if not entries:
        return b""
    hex_str = entries[0].get("hex", "")
    return bytes.fromhex(hex_str)


def _counter_value(lsp) -> int:
    b = _counter_blob(lsp)
    if len(b) < 4:
        return -1
    return int.from_bytes(b[:4], "little")


def test_counter_increments_per_factory_create(ss_node_factory):
    """Two factory-creates on a single plugin instance produce iids
    with counter 0 and 1 respectively. The persisted counter ends at
    2 (the next value to be consumed)."""
    lsp = ss_node_factory.get_node()

    r1 = lsp.rpc.call("factory-create",
        {"funding_sats": 100_000, "clients": [FAKE_CLIENT_ID]})
    iid1 = r1["instance_id"]
    after_first = _counter_value(lsp)
    assert after_first == 1, (
        f"counter should be 1 after first create, got {after_first}")

    r2 = lsp.rpc.call("factory-create",
        {"funding_sats": 100_000, "clients": [FAKE_CLIENT_ID_2]})
    iid2 = r2["instance_id"]
    after_second = _counter_value(lsp)
    assert after_second == 2, (
        f"counter should be 2 after second create, got {after_second}")

    assert iid1 != iid2, (
        "distinct iids expected — counter must break same-block ties")


def test_counter_survives_restart(ss_node_factory):
    """Create a factory, restart the plugin, create another. The
    second factory's iid must be derived from counter=1 (not 0),
    proving the persisted counter was reloaded on restart."""
    lsp = ss_node_factory.get_node()
    lsp.rpc.call("factory-create",
        {"funding_sats": 100_000, "clients": [FAKE_CLIENT_ID]})
    assert _counter_value(lsp) == 1

    # Restart the node — datastore persists, in-memory state resets.
    lsp.restart()

    # New factory after restart should see counter=1 loaded.
    lsp.rpc.call("factory-create",
        {"funding_sats": 100_000, "clients": [FAKE_CLIENT_ID_2]})
    assert _counter_value(lsp) == 2, (
        "counter must advance to 2 after restart + create — "
        "counter was not reloaded from datastore")
