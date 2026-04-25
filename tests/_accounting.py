"""Shared accounting helpers for SuperScalar CLN plugin tests.

These utilities decode on-chain transactions via bitcoind RPC and the
plugin's persisted-tx datastore so tests can assert sum-conservation
across factory ceremonies, chain advances, and close paths.

The plugin doesn't expose per-leaf output amounts on factory-list, so
all amount checks read either:
  - the funding TX from bitcoind (after the ceremony confirms it), OR
  - persisted signed leaf TXs from CLN's datastore
                (key path: superscalar/factories/{iid}/signed_txs)

Decoding piggybacks on bitcoind's `decoderawtransaction` rather than
parsing manually — saves ~150 LOC of varint/segwit handling and exactly
matches what consensus would compute.

Conventions:
  - All amounts are in SATS (not msat or BTC). Bitcoind returns BTC
    floats, so we convert via round(btc * 1e8). pyln-testing's regtest
    runs at ~1e-8 BTC precision so the round is exact.
  - Tx fee for an input set + output set is computed as
    sum(input_amounts) - sum(output_amounts). Caller supplies the
    input amount(s).
"""
from __future__ import annotations

import time
from typing import Iterable


# ---------- TX decoding ----------

def decode_tx(node, rawhex: str) -> dict:
    """decoderawtransaction wrapper. Returns the parsed dict."""
    return node.bitcoin.rpc.decoderawtransaction(rawhex, True)


def get_tx_from_chain(node, txid: str) -> dict:
    """Fetch a confirmed TX from bitcoind. Raises if not found."""
    raw = node.bitcoin.rpc.getrawtransaction(txid, True)
    if isinstance(raw, str):
        # legacy verbose=False — re-decode
        return node.bitcoin.rpc.decoderawtransaction(raw, True)
    return raw


def btc_to_sats(btc) -> int:
    """Bitcoind returns output amounts as Decimal (or float). Convert to
    int sats. Handles Decimal exactly via int + scaling, falls back to
    float for primitive numeric inputs."""
    from decimal import Decimal
    if isinstance(btc, Decimal):
        # Exact: BTC values come at 1e-8 precision, multiply then round
        return int((btc * Decimal(10) ** 8).to_integral_value())
    return int(round(float(btc) * 1e8))


def output_sats(tx: dict) -> list[int]:
    """Return the int-sat value of each output, in vout order."""
    return [btc_to_sats(v["value"]) for v in tx["vout"]]


def output_spk(tx: dict, vout: int) -> str:
    """Hex script-pubkey of a specific output (used for routing assertions)."""
    return tx["vout"][vout]["scriptPubKey"]["hex"]


# ---------- Datastore access ----------

def datastore_read_hex(node, key_path: list[str]) -> bytes | None:
    """Read a hex-encoded datastore value as raw bytes, or None if absent."""
    try:
        r = node.rpc.listdatastore(key_path)
    except Exception:
        return None
    entries = r.get("datastore") or []
    if not entries:
        return None
    hex_str = entries[0].get("hex")
    if not hex_str:
        return None
    return bytes.fromhex(hex_str)


def get_signed_txs_for_factory(node, iid: str) -> dict[int, bytes]:
    """Read the persisted signed_txs blob from the plugin's datastore and
    parse it into {node_idx -> signed_tx_bytes}.

    Format (matches ss_persist_serialize_signed_txs in persist.c):
      n_nodes (u16 BE)
      for each: node_idx (u16 BE) + txid (32) + tx_len (u32 BE) + tx (tx_len)
    """
    raw = datastore_read_hex(node,
                             ["superscalar", "factories", iid, "signed_txs"])
    if raw is None or len(raw) < 2:
        return {}
    n = int.from_bytes(raw[:2], "big")
    out: dict[int, bytes] = {}
    p = 2
    for _ in range(n):
        if p + 2 + 32 + 4 > len(raw):
            break
        node_idx = int.from_bytes(raw[p:p + 2], "big"); p += 2
        p += 32  # skip txid (we'll re-derive from the TX)
        tx_len = int.from_bytes(raw[p:p + 4], "big"); p += 4
        if p + tx_len > len(raw):
            break
        out[node_idx] = raw[p:p + tx_len]
        p += tx_len
    return out


def get_ps_chain_entry(node, iid: str, leaf_node_idx: int,
                      chain_pos: int) -> tuple[bytes, int, bytes] | None:
    """Read a PS chain entry from the datastore. Returns (txid, chan_amt, tx_bytes) or None.

    Format (matches ss_persist_serialize_ps_chain_entry):
      txid (32) + chan_amount_sats (u64 BE) + tx_len (u32 BE) + tx (tx_len)
    """
    key = ["superscalar", "factories", iid, "ps_chain",
           str(leaf_node_idx), str(chain_pos)]
    raw = datastore_read_hex(node, key)
    if raw is None or len(raw) < 32 + 8 + 4:
        return None
    txid = raw[:32]
    chan_amt = int.from_bytes(raw[32:40], "big")
    tx_len = int.from_bytes(raw[40:44], "big")
    if 44 + tx_len > len(raw):
        return None
    tx = raw[44:44 + tx_len]
    return (txid, chan_amt, tx)


# ---------- Conservation checks ----------

def assert_outputs_conserve(tx: dict, input_amount_sats: int,
                            *, max_fee_sats: int | None = None) -> int:
    """Assert sum(outputs) <= input_amount, and return the implied fee.

    Optionally enforce an upper bound on the fee (catches "ate the
    whole input" bugs where an output amount got zeroed).
    """
    out_sum = sum(output_sats(tx))
    fee = input_amount_sats - out_sum
    assert fee >= 0, (
        f"outputs sum to {out_sum} sats but input was only "
        f"{input_amount_sats} sats — negative fee impossible")
    if max_fee_sats is not None:
        assert fee <= max_fee_sats, (
            f"implied fee {fee} sats exceeds max_fee_sats={max_fee_sats}")
    return fee


def assert_close_to(actual: int, expected: int, *, tol: int,
                    label: str = "amount") -> None:
    """Assert |actual - expected| <= tol. Tolerance accommodates per-tx
    fee variation that's not statically knowable (factory_t fee config
    vs the actual fee_per_tx applied to a specific node)."""
    diff = abs(actual - expected)
    assert diff <= tol, (
        f"{label}: expected {expected} sats (±{tol}), got {actual} "
        f"(diff={diff})")


# ---------- Funding-TX introspection ----------

def get_factory_funding_amount(lsp, iid: str) -> int:
    """Resolve the factory's on-chain funding output amount.

    The plugin records funding_txid + funding_outnum on factory-list
    but not the amount itself, so we look up the TX on-chain and read
    the value at the recorded vout. This is the SOURCE OF TRUTH for
    accounting tests: whatever bitcoind says was funded is the input
    to the tree."""
    f = next(x for x in lsp.rpc.call("factory-list")["factories"]
             if x["instance_id"] == iid)
    txid = f["funding_txid"]
    vout = f["funding_outnum"]
    assert txid != "0" * 64, (
        "factory-list reports zero funding_txid — ceremony didn't "
        "broadcast or didn't record the funding TX")
    tx = get_tx_from_chain(lsp, txid)
    return btc_to_sats(tx["vout"][vout]["value"])


def find_factory_funding_output(node, funding_txid: str,
                                expected_amount_sats: int) -> tuple[int, int]:
    """Locate the factory's funding output in the on-chain TX. Returns
    (vout, amount_sats). Identifies by amount (the wallet's other
    outputs are change with arbitrary values; the factory output is the
    one matching the requested funding_sats). Falls back to the largest
    output if no exact match (CLN's withdraw subtracts a tx-fee, so the
    actual factory output may be N-fee sats)."""
    tx = get_tx_from_chain(node, funding_txid)
    outs = output_sats(tx)
    # Exact match first
    for vout, amt in enumerate(outs):
        if amt == expected_amount_sats:
            return (vout, amt)
    # Closest match within 5000 sats (CLN withdraw fee ceiling)
    best = min(range(len(outs)),
               key=lambda i: abs(outs[i] - expected_amount_sats))
    if abs(outs[best] - expected_amount_sats) <= 5000:
        return (best, outs[best])
    raise AssertionError(
        f"no output in {funding_txid} matches expected funding "
        f"{expected_amount_sats} sats (outputs: {outs})")


# ---------- Ceremony progression helpers ----------

def wait_metric(node, pattern: str, *, timeout: float = 15.0) -> str:
    """Poll node logs for a regex match. Tests use this to confirm
    ceremony sub-steps fired."""
    import re
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        for line in node.daemon.logs:
            if rx.search(line):
                return line
        time.sleep(0.2)
    raise TimeoutError(
        f"metric pattern {pattern!r} not seen within {timeout}s")
