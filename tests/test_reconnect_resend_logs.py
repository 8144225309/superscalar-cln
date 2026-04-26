"""Re-validation: explicit reconnect-resend log lines after the
dead-code-gate fix (commit 12697f2).

Before that commit, handle_connect early-bailed on `!ss_state.is_lsp`
(a global that was never set anywhere), so the LSP-side resend code
for FACTORY_PROPOSE / ALL_NONCES / ROTATE_PROPOSE / LEAF_ADVANCE_PROPOSE
was unreachable. Tests like test_rotation_reconnect.py passed only
because CLN's connectd was queueing custommsgs on dead connections
and re-delivering on reconnect.

These tests force the resend path by:
  1. Starting a ceremony state that triggers an LSP→client message
  2. force-disconnecting the client
  3. reconnecting
  4. asserting the explicit "Reconnect recovery: re-sent X" log line
     appears in the LSP's daemon log

If the log line is missing, the resend is dead code again and we
need to investigate.
"""
from __future__ import annotations

import time

from conftest import (
    create_two_party_factory,
    wait_for_ceremony_complete,
)
from _accounting import wait_metric


def _setup_ps(ss_node_factory, funding_sats=200_000):
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=funding_sats,
                                   timeout=60.0,
                                   arity_mode="arity_ps")
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    return lsp, client, iid


def test_rotate_reconnect_emits_resend_log(ss_node_factory):
    """factory-rotate followed by force-disconnect/reconnect must
    fire the LSP's 'Reconnect recovery: re-sent ROTATE_PROPOSE' log
    line. Without this assertion, the prior test_rotation_reconnect
    only verified that the rotation eventually completed — possibly
    via connectd queueing alone, with the plugin's resend path
    silently dead.

    Use ARITY_1 (default for 2-party) so rotation has the simplest
    code path; the resend logic is shared across arities."""
    lsp, client = ss_node_factory.get_nodes(2)
    lsp.fundwallet(10_000_000)
    lsp.connect(client)
    iid = create_two_party_factory(lsp, client, funding_sats=100_000)
    wait_for_ceremony_complete(lsp, iid, timeout=120.0)

    # Trigger rotation (PROPOSE goes out)
    lsp.rpc.call("factory-rotate", {"instance_id": iid})
    # Disconnect immediately so the in-flight rotation stalls
    client_id = client.info["id"]
    try:
        lsp.rpc.disconnect(client_id, force=True)
    except Exception:
        pass
    time.sleep(1.0)
    # Reconnect — peer_connected must fire the resend
    lsp.connect(client)

    # Wait for the explicit resend log
    wait_metric(lsp, r"Reconnect recovery: re-sent ROTATE_PROPOSE",
                timeout=30.0)


def test_ps_advance_reconnect_emits_resend_log(ss_node_factory):
    """factory-ps-advance followed by force-disconnect/reconnect must
    fire 'Reconnect recovery: re-sent LEAF_ADVANCE_PROPOSE' on the
    LSP. Direct evidence the cached_ps_propose_wire path is alive."""
    lsp, client, iid = _setup_ps(ss_node_factory)
    client_id = client.info["id"]

    # Disconnect FIRST so PROPOSE has nowhere to go (queued by
    # connectd or dropped — either way the ceremony stalls pending)
    try:
        lsp.rpc.disconnect(client_id, force=True)
    except Exception:
        pass
    time.sleep(0.5)

    # Kick off the advance — pending state is set synchronously
    lsp.rpc.call("factory-ps-advance",
                 {"instance_id": iid, "leaf_side": 0})

    # Reconnect — peer_connected must fire the resend
    lsp.connect(client)

    # Wait for the explicit resend log line
    wait_metric(lsp,
                r"Reconnect recovery: re-sent LEAF_ADVANCE_PROPOSE",
                timeout=30.0)
