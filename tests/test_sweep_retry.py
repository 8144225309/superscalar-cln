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

Test strategy: drive the retry state machine entirely via dev RPCs so
the test is deterministic and independent of block_added timing.
  - dev-factory-inject-sweep: register the entry
  - dev-factory-tick-sweep-scheduler: advance state machine at a
    given block height (no real broadcast; only state transitions)
  - dev-factory-mark-sweep-failed: simulate a failed broadcast at a
    given block (READY → FAILED with broadcast_block set)
"""
from __future__ import annotations

import time

FAKE_CLIENT_ID = "02" + "00" * 32

SS_SWEEP_MAX_RETRIES = 3
SS_SWEEP_RETRY_DELAY_BLOCKS = 6


def _create_factory(lsp, funding_sats=100_000):
    r = lsp.rpc.call("factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]})
    return r["instance_id"]


def _factory(lsp, iid):
    for f in lsp.rpc.call("factory-list")["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not found")


def _sweep(lsp, iid, vout):
    fs = _factory(lsp, iid)
    for s in fs.get("pending_sweeps", []):
        if s["source_vout"] == vout:
            return s
    raise AssertionError(f"no pending sweep with source_vout={vout}")


def _wait_sweep_state(lsp, iid, vout, allowed, timeout=5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        fs = _factory(lsp, iid)
        for s in fs.get("pending_sweeps", []):
            if s["source_vout"] == vout:
                last = s["state"]
                if last in allowed:
                    return last
        time.sleep(0.1)
    raise AssertionError(
        f"sweep vout={vout} stayed at {last!r}, expected one of "
        f"{allowed} within {timeout}s")


def test_failed_sweep_retries_after_cooldown(ss_node_factory):
    """Drive the retry state machine deterministically via dev RPCs.

    Each retry cycle:
      1. dev-factory-tick-sweep-scheduler at block B → FAILED→READY
         (once the cooldown B >= broadcast_block + RETRY_DELAY has elapsed)
      2. dev-factory-mark-sweep-failed → READY→FAILED with broadcast_block=B

    After SS_SWEEP_MAX_RETRIES retries the tick produces 0 transitions
    (reserved[0] == MAX → no more retries), and the entry stays FAILED.
    """
    lsp = ss_node_factory.get_node(
        broken_log=r"sweep broadcast FAILED|sendrawtransaction|sweep: entry .* RETRY",
    )
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 9,
        "amount_sats": 50_000,
        "csv_delay": 0,
        "confirmed_block": 1,
    })

    # PENDING → READY: csv_delay=0, confirmed_block=1, tick at block 10.
    r = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                     {"instance_id": iid, "block_height": 10})
    assert r["transitions"] == 1, (
        f"expected 1 transition (PENDING→READY), got {r['transitions']}")
    _wait_sweep_state(lsp, iid, 9, {"ready"})

    # Drive 3 retry cycles. Each cycle:
    #   mark-sweep-failed(broadcast_block=B)  →  state=FAILED
    #   tick(block=B + DELAY + 1)             →  state=READY, RETRY N/3 logged
    base = 10
    for attempt in range(SS_SWEEP_MAX_RETRIES):
        broadcast_block = base + attempt * (SS_SWEEP_RETRY_DELAY_BLOCKS + 2)

        lsp.rpc.call("dev-factory-mark-sweep-failed", {
            "instance_id": iid,
            "source_vout": 9,
            "broadcast_block": broadcast_block,
        })
        _wait_sweep_state(lsp, iid, 9, {"failed"})

        retry_block = broadcast_block + SS_SWEEP_RETRY_DELAY_BLOCKS + 1
        r = lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                         {"instance_id": iid, "block_height": retry_block})
        assert r["transitions"] == 1, (
            f"attempt {attempt + 1}: expected 1 transition (FAILED→READY), "
            f"got {r['transitions']}")
        _wait_sweep_state(lsp, iid, 9, {"ready"})

    # 4th failure: reserved[0] == SS_SWEEP_MAX_RETRIES → no more retries.
    last_broadcast_block = base + SS_SWEEP_MAX_RETRIES * (SS_SWEEP_RETRY_DELAY_BLOCKS + 2)
    lsp.rpc.call("dev-factory-mark-sweep-failed", {
        "instance_id": iid,
        "source_vout": 9,
        "broadcast_block": last_broadcast_block,
    })
    r = lsp.rpc.call("dev-factory-tick-sweep-scheduler", {
        "instance_id": iid,
        "block_height": last_broadcast_block + SS_SWEEP_RETRY_DELAY_BLOCKS + 1,
    })
    assert r["transitions"] == 0, (
        f"after {SS_SWEEP_MAX_RETRIES} retries, expected 0 transitions; "
        f"got {r['transitions']}")

    # All 3 RETRY log lines must have fired.
    assert lsp.daemon.is_in_log(r"sweep: entry .* RETRY 1/3"), "RETRY 1/3 not logged"
    assert lsp.daemon.is_in_log(r"sweep: entry .* RETRY 2/3"), "RETRY 2/3 not logged"
    assert lsp.daemon.is_in_log(r"sweep: entry .* RETRY 3/3"), "RETRY 3/3 not logged"

    # Final state is failed (operator-review terminal).
    entry = _sweep(lsp, iid, 9)
    assert entry["state"] == "failed", (
        f"after {SS_SWEEP_MAX_RETRIES} retries, sweep should rest at failed; "
        f"got {entry['state']}")
