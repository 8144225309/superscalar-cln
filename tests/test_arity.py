"""Tier 3.9 — Dynamic arity and early_warning_time correctness.

ss_choose_arity(n_total):
    n_total <= 2  →  ARITY_1  (each party on own leaf, 2-of-2 exit)
    n_total >= 3  →  ARITY_2  (pairs per leaf, shallower tree)

compute_early_warning_time was previously buggy:
    - Used wrong leaf-count formula: (n_clients+1)/2 instead of
      ceil(n_total/2) = (n_total+1)/2 = (n_clients+2)/2.
    - Special-cased n_clients<=1 → n_layers=1, which is wrong for
      n_clients=1/ARITY_1 (should be 2 layers, depth=1).

These tests verify the corrected early_warning_time values by creating
factories with known participant counts and asserting the `early_warning_time`
field reported by factory-list matches the analytic formula.

Expected EWT values (DW_STEP_BLOCKS=144, DW_STATES_PER_LAYER=16):
  per_layer = 144 * 15 + 6 = 2166 blocks
  EWT(n_layers) = n_layers * 2166 + 36

  n_clients=1 (n_total=2, ARITY_1): leaves=2, depth=1, layers=2 → 4368
  n_clients=2 (n_total=3, ARITY_2): leaves=2, depth=1, layers=2 → 4368
  n_clients=3 (n_total=4, ARITY_2): leaves=2, depth=1, layers=2 → 4368
  n_clients=4 (n_total=5, ARITY_2): leaves=3, depth=2, layers=3 → 6534
  n_clients=7 (n_total=8, ARITY_2): leaves=4, depth=2, layers=3 → 6534
  n_clients=8 (n_total=9, ARITY_2): leaves=5, depth=3, layers=4 → 8700
"""
from __future__ import annotations

FAKE_CLIENT_IDS = [
    "02" + hex(i + 1)[2:].zfill(64)
    for i in range(16)
]

DW_STEP_BLOCKS = 144
DW_STATES_PER_LAYER = 16


def _ewt(n_layers: int) -> int:
    return n_layers * (DW_STEP_BLOCKS * (DW_STATES_PER_LAYER - 1) + 6) + 36


def _create(lsp, n_clients: int, funding_sats: int = 500_000,
            arity_mode: str | None = None) -> dict:
    clients = FAKE_CLIENT_IDS[:n_clients]
    payload = {"funding_sats": funding_sats, "clients": clients}
    if arity_mode is not None:
        payload["arity_mode"] = arity_mode
    r = lsp.rpc.call("factory-create", payload)
    iid = r["instance_id"]
    for f in lsp.rpc.call("factory-list")["factories"]:
        if f["instance_id"] == iid:
            return f
    raise AssertionError(f"factory {iid} not found")


def test_ewt_one_client(ss_node_factory):
    """n_clients=1 (n_total=2): ARITY_1, 2 leaves, depth=1, 2 DW layers."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=1)
    assert f["early_warning_time"] == _ewt(2), (
        f"n_clients=1: expected ewt={_ewt(2)}, got {f['early_warning_time']}")


def test_ewt_two_clients(ss_node_factory):
    """n_clients=2 (n_total=3): ARITY_2, 2 leaves, depth=1, 2 DW layers."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=2)
    assert f["early_warning_time"] == _ewt(2), (
        f"n_clients=2: expected ewt={_ewt(2)}, got {f['early_warning_time']}")


def test_ewt_three_clients(ss_node_factory):
    """n_clients=3 (n_total=4): ARITY_2, 2 leaves, depth=1, 2 DW layers."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=3)
    assert f["early_warning_time"] == _ewt(2), (
        f"n_clients=3: expected ewt={_ewt(2)}, got {f['early_warning_time']}")


def test_ewt_four_clients(ss_node_factory):
    """n_clients=4 (n_total=5): ARITY_2, 3 leaves, depth=2, 3 DW layers.
    Previously buggy: old formula reported _ewt(2)=4368 instead of _ewt(3)=6534."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=4)
    assert f["early_warning_time"] == _ewt(3), (
        f"n_clients=4: expected ewt={_ewt(3)}, got {f['early_warning_time']}")


def test_ewt_seven_clients(ss_node_factory):
    """n_clients=7 (n_total=8): ARITY_2, 4 leaves, depth=2, 3 DW layers."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=7)
    assert f["early_warning_time"] == _ewt(3), (
        f"n_clients=7: expected ewt={_ewt(3)}, got {f['early_warning_time']}")


def test_ewt_eight_clients(ss_node_factory):
    """n_clients=8 (n_total=9): ARITY_2, 5 leaves, depth=3, 4 DW layers."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=8)
    assert f["early_warning_time"] == _ewt(4), (
        f"n_clients=8: expected ewt={_ewt(4)}, got {f['early_warning_time']}")


# ------- Tier 2.6: arity_mode knob + ARITY_PS EWT savings -------

def test_arity_mode_auto_matches_default(ss_node_factory):
    """arity_mode="auto" behaves identically to omitting the param."""
    lsp = ss_node_factory.get_node()
    f1 = _create(lsp, n_clients=3)                       # omitted
    f2 = _create(lsp, n_clients=3, arity_mode="auto")   # explicit auto
    assert f1["early_warning_time"] == f2["early_warning_time"]
    assert f1["arity_mode"] == f2["arity_mode"] == "arity_2"
    assert f1["tree_mode"] == f2["tree_mode"] == "dw"


def test_arity_mode_explicit_arity_1(ss_node_factory):
    """arity_mode="arity_1" forces one-client-per-leaf even with 3 clients.
    n_total=4, ARITY_1: leaves=4, depth=2, layers=3 → _ewt(3)=6534.
    Default (arity_2) for n=3 would give _ewt(2)=4368."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=3, arity_mode="arity_1")
    assert f["arity_mode"] == "arity_1"
    assert f["tree_mode"] == "dw"
    assert f["early_warning_time"] == _ewt(3), (
        f"arity_1 forced: expected ewt={_ewt(3)}, got {f['early_warning_time']}")


def test_arity_mode_ps_saves_one_layer(ss_node_factory):
    """arity_mode="arity_ps" uses PS leaves; EWT drops by one leaf-layer
    (DW_STEP_BLOCKS*(DW_STATES_PER_LAYER-1) + 6 = 2166 blocks) vs arity_1.
    n_clients=3 → leaves=4, depth=2, layers=3. PS EWT = 3*2166 + 36 - 2166
                = 6534 - 2166 = 4368."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=3, arity_mode="arity_ps")
    assert f["arity_mode"] == "arity_ps"
    assert f["tree_mode"] == "ps"
    expected = _ewt(3) - (DW_STEP_BLOCKS * (DW_STATES_PER_LAYER - 1) + 6)
    assert f["early_warning_time"] == expected, (
        f"arity_ps: expected ewt={expected}, got {f['early_warning_time']}")


def test_arity_mode_ps_alias(ss_node_factory):
    """arity_mode="ps" is an accepted alias for "arity_ps"."""
    lsp = ss_node_factory.get_node()
    f = _create(lsp, n_clients=3, arity_mode="ps")
    assert f["arity_mode"] == "arity_ps"


def test_arity_mode_invalid_rejected(ss_node_factory):
    """Unknown arity_mode strings are rejected cleanly by the RPC."""
    import pytest
    from pyln.client import RpcError
    lsp = ss_node_factory.get_node()
    clients = FAKE_CLIENT_IDS[:2]
    with pytest.raises(RpcError):
        lsp.rpc.call("factory-create", {
            "funding_sats": 500_000,
            "clients": clients,
            "arity_mode": "bogus",
        })
