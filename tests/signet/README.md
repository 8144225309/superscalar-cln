# Signet smoke tests

These are manual / semi-manual scripts that drive a known-good scenario through two live CLN signet nodes with the superscalar plugin loaded. They are NOT part of CI — the CLN integration tests in `tests/` are the automated counterpart (planned, not yet implemented as of this writing).

## Why signet?

- Real chain, real MuSig2, real custommsg transport, real CLN.
- Faucet sats are free and fast enough for iterative runs.
- We have persistent nodes on the VPS whose HSM keys are stable, so we can re-run scripts without re-funding each time.

Regtest is faster but misses edge cases that come from real signet block timing (factory early-warning windows, BIP-68 interactions).

## Prerequisites

- Two CLN nodes running on signet with the superscalar plugin loaded:
  - LSP node (default: `/var/lib/cln-blip56`)
  - Client node (default: `/var/lib/cln-signet-b`)
- `bitcoind` on signet reachable via `bitcoin-cli -signet`
- LSP's on-chain wallet funded (a few 100k sats)
- The two nodes know about each other (at least one has called `connect` on the other)
- Plugin binary built and deployed to both nodes' plugin directories
- **Both daemons restarted AFTER the plugin binary was last rebuilt.** lightningd forks its plugins at daemon startup and keeps those child processes for the life of the daemon. Rebuilding the plugin binary on disk does nothing for an already-running daemon — the old fork is still what processes hooks. `lightning-cli stop && lightningd --daemon ...` (or equivalent) is required before any test run that exercises code added since the last restart.

## Scripts

| Script | Covers | Runtime |
|---|---|---|
| `smoke_basic.sh` | Create factory → verify meta persists → rotate → verify REVOKE_ACK | ~30s |
| `smoke_revoke_ack.sh` | Kill client mid-REVOKE → verify LSP resends on reconnect → verify rotate blocks until acked | ~60s |

## Running

On the VPS:

```bash
cd /root/superscalar-cln/tests/signet
./smoke_basic.sh
./smoke_revoke_ack.sh
```

Each script exits non-zero on any failed assertion and echoes the failing line.

## Overriding defaults

```bash
LSP_DIR=/var/lib/cln-blip56 \
CLIENT_DIR=/var/lib/cln-signet-b \
CLI=/root/lightning/cli/lightning-cli \
./smoke_basic.sh
```

## What these scripts do NOT cover

- Multi-client factories (arity-2, 3-party)
- Breach response (needs bitcoin-cli raw TX injection — separate script)
- HTLC early-warning close (needs specific block-height setup — separate script)
- Startup catch-up (needs plugin restart mid-run — separate script)

These are next on the list, but each deserves its own script + careful setup. Once the pyln-testing harness lands in `tests/`, that'll be the preferred place for exhaustive scenario coverage; signet smoke stays focused on "does the happy path still work end-to-end on a real chain with a real HSM".
