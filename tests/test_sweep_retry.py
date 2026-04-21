"""Phase 4d3 — auto-retry FAILED sweeps.

When a sweep broadcast is rejected by bitcoind (unknown UTXO, mempool
conflict, etc.), the entry drops to SWEEP_STATE_FAILED. v1 left it
there for operator review. 4d3 auto-retries after a cooldown,
bounded to SS_SWEEP_MAX_RETRIES attempts.

State transitions:
    READY → (kickoff fails) → FAILED
    FAILED + current_block >= broadcast_block + 6
           + reserved[0] < 3  → READY (retry_count++)
    READY → (kickoff) → BROADCAST → (bitcoind rejects) → FAILED → ...
    After 3 retries the entry sticks at FAILED for operator review.
"""
from __future__ import annotations

import time

FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats=100_000):
    r = lsp.rpc.call("factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]})
    return r["instance_id"]


def _factory(lsp, iid):
    for f in lsp.rpc.call("factory-list")["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not found")


def _wait_sweep_state(lsp, iid, vout, allowed, timeout=15.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        fs = _factory(lsp, iid)
        for s in fs.get("pending_sweeps", []):
            if s["source_vout"] == vout:
                last = s["state"]
                if last in allowed:
                    return last
        time.sleep(0.3)
    raise AssertionError(
        f"sweep vout={vout} stayed at {last!r}, expected one of "
        f"{allowed} within {timeout}s")


def test_failed_sweep_retries_after_cooldown(ss_node_factory, bitcoind):
    """Inject a sweep with non-zero synthetic txid so auto-kickoff
    fires. bitcoind rejects (unknown UTXO) → state=FAILED. Generate
    blocks past the retry cooldown (6 blocks) and verify the entry
    retries (reserved[0] increments, state bounces READY→FAILED again,
    eventually sticks at FAILED after 3 attempts).

    factory-list doesn't surface retry_count today; we observe the
    retry indirectly via log markers and via the state bouncing
    (which the block_added auto-kickoff drives)."""
    lsp = ss_node_factory.get_node(
        broken_log=r"sweep broadcast FAILED|sendrawtransaction|sweep: entry .* RETRY",
    )
    iid = _create_factory(lsp)

    # csv_delay=0 + confirmed_block=1 so first block_added bumps to
    # READY + fires kickoff immediately.
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 9,
        "amount_sats": 50_000,
        "csv_delay": 0,
        "confirmed_block": 1,
    })

    # First block: PENDING → READY → kickoff → BROADCAST → FAILED.
    bitcoind.generate_block(1)
    state = _wait_sweep_state(lsp, iid, 9,
                              allowed={"failed", "broadcast"},
                              timeout=15.0)
    assert state in {"failed", "broadcast"}

    # Advance past retry cooldown (6 blocks) and confirm retry fires.
    # Each retry cycle: FAILED → READY (on scheduler tick) →
    # BROADCAST (on kickoff) → FAILED (on bitcoind rejection). The log
    # should show at least one "RETRY" line.
    for _ in range(20):
        bitcoind.generate_block(1)
        time.sleep(0.5)

    # After generous block advancement + cooldown, the entry should
    # have exhausted retries and stuck at failed. Assert via log
    # regex that the retry path actually fired.
    assert lsp.daemon.is_in_log(r"sweep: entry .* RETRY 1/3") \
        or lsp.daemon.is_in_log(r"sweep: entry .* RETRY 2/3") \
        or lsp.daemon.is_in_log(r"sweep: entry .* RETRY 3/3"), (
        "expected at least one RETRY log line — retry path didn't fire")

    # Final state is failed (operator-review terminal).
    fs = _factory(lsp, iid)
    entry = next(s for s in fs["pending_sweeps"] if s["source_vout"] == 9)
    assert entry["state"] == "failed", (
        f"after 3 retries, sweep should rest at failed; got "
        f"{entry['state']}")
