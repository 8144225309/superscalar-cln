"""Phase 5b probe test — does a real two-party ceremony complete
end-to-end in regtest?

This is the empirical "find out what's actually blocked" test.
Extends the existing create_two_party_factory helper to wait for
ceremony-complete instead of just meta-persisted. Runs against real
regtest bitcoind + two plugin-loaded CLN nodes connected via CLN's
own custommsg 33001 pipe.

Expected outcomes:
    PASS:   5b's "blocker" was overstated; ceremony works, we just
            need more tests. No harness changes required.
    FAIL with specific error: tells us exactly where the pipeline
            breaks (NONCE exchange, signing, etc.). Informs scope.
"""
from __future__ import annotations

import pytest


def test_two_party_ceremony_reaches_complete(ss_node_factory):
    """LSP + one client, both plugin-loaded. LSP calls factory-create,
    we wait for ceremony=complete. If the custommsg 33001 pipe works
    and both sides cooperate, this should succeed in under a minute."""
    from conftest import (
        create_two_party_factory,
        wait_for_ceremony_complete,
    )

    lsp, client = ss_node_factory.get_nodes(2)

    # LSP needs funds for the factory's funding TX.
    lsp.fundwallet(10_000_000)

    # Connect so 33001 custommsg can flow.
    lsp.connect(client)

    # factory-create returns immediately; meta persists during NONCE
    # exchange. The existing helper waits for meta only.
    iid = create_two_party_factory(lsp, client,
                                   funding_sats=100_000,
                                   timeout=60.0)

    # Now wait for the ceremony to actually complete.
    final_state = wait_for_ceremony_complete(lsp, iid, timeout=120.0)
    assert final_state == "complete"

    # Verify factory-list reports lifecycle=active too (ceremony-
    # complete implies ready-for-channel-ops).
    out = lsp.rpc.call("factory-list")
    entry = next(f for f in out["factories"]
                 if f["instance_id"] == iid)
    # Lifecycle will be "init" if ceremony done but channels not yet
    # opened, or "active" if factory is fully up. Accept either.
    assert entry["lifecycle"] in {"init", "active"}, (
        f"unexpected lifecycle {entry['lifecycle']!r} after ceremony "
        f"complete"
    )
