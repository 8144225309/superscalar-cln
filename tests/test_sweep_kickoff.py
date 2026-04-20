"""Phase 4d2 — sweep kickoff (READY → BROADCAST real broadcast path).

Unlike test_sweep_scheduler.py which drives state manually via
dev-factory-mark-sweep-broadcast, these tests exercise the real
production kickoff: the block_added hook ticks the scheduler AND
calls ss_sweep_kick_all_ready when entries become READY. This fires
the full pipeline:

    newaddr → ss_build_p2tr_keypath_sweep_hex (real secp +
    BIP-341 tweak + Schnorr sig) → sendrawtransaction

Since the synthetic source UTXO doesn't exist in bitcoind's UTXO
set, sendrawtransaction rejects with -25 and the entry demotes to
FAILED. That outcome proves every link in the chain is wired —
newaddr returns, sweep_builder signs, broadcast fires, reply
classifies. A stuck READY indicates a wiring regression.
"""
from __future__ import annotations

import time

FAKE_CLIENT_ID = "02" + "00" * 32


def _create_factory(lsp, funding_sats: int = 100_000) -> str:
    r = lsp.rpc.call(
        "factory-create",
        {"funding_sats": funding_sats, "clients": [FAKE_CLIENT_ID]},
    )
    return r["instance_id"]


def _factory(lsp, iid: str) -> dict:
    out = lsp.rpc.call("factory-list")
    for f in out["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not in factory-list")


def _wait_sweep_state(lsp, iid, vout, allowed, timeout=20.0):
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
        f"sweep source_vout={vout} stayed at {last!r}, expected one of "
        f"{allowed} within {timeout}s"
    )


def test_block_added_drives_scheduler_then_kickoff(ss_node_factory, bitcoind):
    """Inject a sweep with csv_delay=0 + confirmed_block=1 (any tip
    height ≥1 satisfies maturity on regtest). Generate a block so the
    block_added hook fires: scheduler ticks PENDING → READY, then
    ss_sweep_kick_all_ready fires the newaddr → build →
    sendrawtransaction chain. The synthetic source UTXO is missing so
    bitcoind rejects; the entry eventually reaches FAILED (or at least
    moves past READY through BROADCAST)."""
    lsp = ss_node_factory.get_node(
        broken_log=r"sweep broadcast FAILED|sendrawtransaction",
    )
    iid = _create_factory(lsp)

    # csv_delay=0 + confirmed_block=1 guarantees PENDING → READY on the
    # very next scheduler tick after the next block add.
    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 7,
        "amount_sats": 50_000,
        "csv_delay": 0,
        "confirmed_block": 1,
    })

    # Drive a block so handle_block_added fires in the plugin.
    bitcoind.generate_block(1)

    state = _wait_sweep_state(lsp, iid, 7,
                              allowed={"broadcast", "failed"},
                              timeout=20.0)
    assert state in {"broadcast", "failed"}, state


def test_dev_tick_does_not_auto_kickoff(ss_node_factory):
    """Regression guard: the dev-factory-tick-sweep-scheduler RPC
    advances state machine transitions but must NOT fire the kickoff
    chain. Existing test_sweep_scheduler.py tests rely on this — they
    mark-broadcast READY entries manually. If dev-tick ever starts
    auto-kicking, those tests (and this one) fail."""
    lsp = ss_node_factory.get_node()
    iid = _create_factory(lsp)

    lsp.rpc.call("dev-factory-inject-sweep", {
        "instance_id": iid,
        "type": "factory_leaf",
        "source_vout": 3,
        "amount_sats": 40_000,
        "csv_delay": 5,
        "confirmed_block": 100,
    })

    lsp.rpc.call("dev-factory-tick-sweep-scheduler",
                 {"instance_id": iid, "block_height": 110})

    # Even waiting a bit, state should stay at READY: no broadcast,
    # no failed.
    time.sleep(2.0)

    fs = _factory(lsp, iid)
    sweeps = [s for s in fs["pending_sweeps"] if s["source_vout"] == 3]
    assert len(sweeps) == 1
    assert sweeps[0]["state"] == "ready", (
        f"dev-tick must not auto-kickoff; expected ready, got "
        f"{sweeps[0]['state']}"
    )
