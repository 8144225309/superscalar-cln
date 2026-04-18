#!/bin/bash
# smoke_revoke_ack.sh — REVOKE_ACK durability and resend on reconnect.
#
# This is the test that would have caught the revoke-ack bug that PR #4
# exists to fix. The scenario:
#
#   1. Create a factory.
#   2. Start a rotation.
#   3. After the LSP sends REVOKE but before the client has acked,
#      kill the client's lightningd process.
#   4. Try to rotate again — the LSP should refuse, because it's still
#      waiting on an ack for the previous epoch.
#   5. Restart the client.
#   6. On reconnect, the LSP should auto-resend the pending REVOKE.
#   7. The client processes it, acks, and now rotate succeeds.
#
# Kill timing is tricky on signet because the REVOKE round-trip is fast.
# We use a grep-polling loop to race the kill into the right window, with
# a fallback that accepts "client already acked before we could kill it"
# as a don't-fail-but-warn outcome (the test is about the durability path,
# not whether we can reliably win the race on every run).

set -euo pipefail

LSP_DIR="${LSP_DIR:-/var/lib/cln-blip56}"
CLIENT_DIR="${CLIENT_DIR:-/var/lib/cln-signet-b}"
CLI="${CLI:-/root/lightning/cli/lightning-cli}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m[revoke-ack]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33mWARN: %s\033[0m\n' "$*"; }
die()   { red "FAIL: $*"; exit 1; }

lsp()    { $CLI --lightning-dir=$LSP_DIR    "$@"; }
client() { $CLI --lightning-dir=$CLIENT_DIR "$@"; }

# Use the most recent factory the LSP knows about. This script is meant to
# run AFTER smoke_basic.sh has created one. If you want to run it in
# isolation, run smoke_basic.sh first or set IID explicitly.
IID="${IID:-$(lsp factory-ladder-status | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    fs = d.get("factories", [])
    if fs:
        print(fs[-1]["instance_id"])
except Exception:
    pass
')}"

[ -n "$IID" ] || die "No factory found. Run smoke_basic.sh first or set IID=<hex>"
info "Using factory $IID"

# Snapshot a marker in the log so our grep doesn't match stale entries from
# previous runs.
MARKER=$(date +%s)
echo "# smoke_revoke_ack marker $MARKER" | tee -a "$LSP_DIR/cln.log" >/dev/null

# -----------------------------------------------------------------------------
# Phase 1: kick off rotation, race to kill the client before it acks
# -----------------------------------------------------------------------------
info "Starting rotation (will kill client before ack)"
(lsp factory-rotate "$IID" &) 2>/dev/null

# Wait for LSP to send REVOKE (log tail after our marker).
timeout=15
while [ $timeout -gt 0 ]; do
    if awk "/# smoke_revoke_ack marker $MARKER/{flag=1;next} flag && /LSP: sent REVOKE/" "$LSP_DIR/cln.log" | grep -q "sent REVOKE"; then
        break
    fi
    sleep 0.2
    timeout=$((timeout - 1))
done
[ $timeout -gt 0 ] || die "LSP did not send REVOKE within 15s — ceremony may have failed earlier"
info "LSP sent REVOKE — racing to kill client before ack"

# Kill the client. We target only the lightningd for this exact datadir to
# avoid murdering unrelated nodes on the VPS. SIGTERM first; if the
# daemon is mid-persist we want it to finish cleanly up to that point
# then die.
CLIENT_PID=$(pgrep -f "lightningd.*lightning-dir=$CLIENT_DIR" | head -1 || true)
if [ -n "$CLIENT_PID" ]; then
    kill -TERM "$CLIENT_PID" 2>/dev/null || true
    # Wait up to 3s for graceful shutdown
    for _ in 1 2 3; do
        kill -0 "$CLIENT_PID" 2>/dev/null || break
        sleep 1
    done
    kill -KILL "$CLIENT_PID" 2>/dev/null || true
    info "Client process $CLIENT_PID killed"
else
    warn "Couldn't find client PID — may have exited already"
fi

# Did we win the race? Check if the ack landed before we killed.
if awk "/# smoke_revoke_ack marker $MARKER/{flag=1;next} flag && /cleared pending REVOKE/" "$LSP_DIR/cln.log" | grep -q "cleared"; then
    warn "Client acked before we could kill it — this run can't test the resend path"
    warn "(Not a failure; the code path is just untested on this particular run)"
    info "Restart client and exit..."
    lightningd --lightning-dir="$CLIENT_DIR" --daemon 2>/dev/null || true
    green "SKIP (raced lost)"
    exit 0
fi

info "Client killed mid-REVOKE (ack not yet sent)"

# -----------------------------------------------------------------------------
# Phase 2: LSP should refuse to rotate again while pending
# -----------------------------------------------------------------------------
info "Attempting factory-rotate while pending ack — should fail"
ROTATE_OUT=$(lsp factory-rotate "$IID" 2>&1 || true)
if echo "$ROTATE_OUT" | grep -q "unacked REVOKE\|Rotation blocked"; then
    green "LSP correctly refused rotate (pending ack)"
else
    die "Expected LSP to refuse rotate; got: $ROTATE_OUT"
fi

# -----------------------------------------------------------------------------
# Phase 3: restart client, expect auto-resend + eventual ack
# -----------------------------------------------------------------------------
info "Restarting client"
lightningd --lightning-dir="$CLIENT_DIR" --daemon 2>/dev/null || true

# Wait for client to come back up.
timeout=30
while [ $timeout -gt 0 ]; do
    if client getinfo >/dev/null 2>&1; then break; fi
    sleep 1
    timeout=$((timeout - 1))
done
[ $timeout -gt 0 ] || die "Client did not come back up within 30s"
info "Client back online"

# After reconnect, LSP should resend REVOKE. Wait for the resend log.
info "Waiting for LSP to resend REVOKE on reconnect..."
timeout=30
while [ $timeout -gt 0 ]; do
    if awk "/# smoke_revoke_ack marker $MARKER/{flag=1;next} flag && /resent REVOKE/" "$LSP_DIR/cln.log" | grep -q "resent"; then
        break
    fi
    sleep 1
    timeout=$((timeout - 1))
done
[ $timeout -gt 0 ] || die "LSP did not resend REVOKE within 30s of reconnect — handle_connect logic broken?"
green "LSP auto-resent REVOKE on reconnect"

# Wait for the ack to land.
info "Waiting for ack to land after resend..."
timeout=30
while [ $timeout -gt 0 ]; do
    if awk "/# smoke_revoke_ack marker $MARKER/{flag=1;next} flag && /cleared pending REVOKE/" "$LSP_DIR/cln.log" | grep -q "cleared"; then
        break
    fi
    sleep 1
    timeout=$((timeout - 1))
done
[ $timeout -gt 0 ] || die "LSP did not receive ack after resend within 30s"
green "Pending ack cleared"

# -----------------------------------------------------------------------------
# Phase 4: rotate should now succeed
# -----------------------------------------------------------------------------
info "Retrying factory-rotate — should now succeed"
ROTATE2=$(lsp factory-rotate "$IID" 2>&1 || true)
if echo "$ROTATE2" | grep -q "unacked REVOKE\|Rotation blocked"; then
    die "LSP still blocked after ack cleared: $ROTATE2"
fi
green "Rotate succeeded after ack"

info "All assertions passed"
green "PASS"
