"""Extract RPC catalog from superscalar.c commands[] array + doc-comments
above each json_* handler. Output a structured Markdown doc."""
import re

with open("/root/superscalar-cln/superscalar.c") as f:
    src = f.read()

# 1) Parse commands[] entries: { "name", handler_fn }
cmd_re = re.compile(r"\{\s*\"([\w\-]+)\",\s*(json_\w+),?\s*\}", re.S)
commands = {}
for m in cmd_re.finditer(src):
    name, handler = m.group(1), m.group(2)
    if "-" in name:
        commands[name] = handler


def extract(name, handler):
    fn_pat = re.compile(
        r"(?:static\s+)?struct command_result\s*\*\s*"
        + re.escape(handler)
        + r"\s*\([^)]*\)\s*\{",
        re.S,
    )
    fn_m = fn_pat.search(src)
    if not fn_m:
        return ("", "")
    fn_start = fn_m.start()
    fn_body_start = fn_m.end()

    depth = 1
    i = fn_body_start
    while i < len(src) and depth > 0:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    body = src[fn_body_start:i]

    params = []
    pm = re.search(r"if \(!param\(cmd[^;]+", body, re.S)
    if pm:
        for entry in re.finditer(r'p_(req|opt)\("([^"]+)"', pm.group(0)):
            req_opt, pname = entry.group(1), entry.group(2)
            suffix = " (req)" if req_opt == "req" else ""
            params.append(pname + suffix)

    prev = src[max(0, fn_start - 2048) : fn_start]
    cm = re.search(r"/\*[*!]?\s*([\s\S]+?)\*/\s*\Z", prev)
    brief = ""
    if cm:
        block = cm.group(1)
        lines = [ln.strip(" *\t") for ln in block.splitlines() if ln.strip(" *\t")]
        for ln in lines:
            if not re.match(r"^=+\s*$", ln) and not ln.startswith("=="):
                brief = ln
                break
        if "." in brief:
            brief = brief.split(".")[0] + "."
        if len(brief) > 140:
            brief = brief[:137] + "..."
    return (", ".join(params) if params else "(none)", brief or "")


categories = {"factory-": [], "wallet-": [], "client-": []}
for name in sorted(commands.keys()):
    for prefix in categories:
        if name.startswith(prefix):
            params, brief = extract(name, commands[name])
            categories[prefix].append((name, params, brief))
            break

md = ["# SuperScalar plugin — RPC catalog", ""]
md.append("Auto-extracted from `superscalar.c` commands[] + handler doc-blocks.")
md.append("Re-run `scripts/gen_rpc_catalog.py` to refresh.")
md.append("")
md.append("Total: " + str(sum(len(v) for v in categories.values())) + " SuperScalar RPCs.")
md.append("")
md.append("**Layer 1 protocol** (BOLT-8 custommsg, wire types `0x0140`-`0x014C`)")
md.append("is not in this catalog — see `CONFORMANCE.md` and `ceremony_wire.h`.")
md.append("All RPCs below are **local** (CLN lightning-rpc Unix socket → plugin).")
md.append("")

prefix_titles = {
    "factory-": "## `factory-*` — protocol & lifecycle RPCs",
    "wallet-":  "## `wallet-*` — local SQLite query/write RPCs (used by the wallet UI)",
    "client-":  "## `client-*` — client-role helpers",
}
for prefix, title in prefix_titles.items():
    md.append(title)
    md.append("")
    md.append("| RPC | Params | Description |")
    md.append("|---|---|---|")
    for name, params, brief in categories[prefix]:
        b = brief.replace("|", "\\|")
        if len(b) > 100:
            b = b[:97] + "..."
        md.append(f"| `{name}` | {params} | {b} |")
    md.append("")

md.append("## CLI defaults vs wallet defaults (task #41 scan)")
md.append("")
md.append("Spot-check of where the wallet quietly defaults a param vs what the CLI requires explicit:")
md.append("")
md.append("| RPC | Wallet behavior | CLI behavior | Divergence? |")
md.append("|---|---|---|---|")
md.append("| `factory-create` | `feerate_perkw=1000` sent if user leaves it blank in modal | CLI rejects without `feerate_perkw` | Convenience only |")
md.append("| `factory-trigger-ceremony` | `force=false` unless toggled | Same default | No |")
md.append("| `factory-rotate` | Just `instance_id` | Same | No |")
md.append("| `factory-browse-host` | Wallet passes `address` hint from local peer record if known | CLI requires manual `address=` | Convenience only |")
md.append("| `factory-join-request` | Same as browse-host | CLI requires manual `address=` | Convenience only |")
md.append("| `wallet-set-operator-pref` | Wallet wraps value in JSON quotes | CLI accepts bare or quoted | Both equivalent |")
md.append("")
md.append("**No protocol-level divergence found.** Every wallet default is local convenience;")
md.append("nothing changes wire behavior between LSP and client.")
md.append("")
md.append("## Wallet usage")
md.append("")
md.append("RPCs the wallet calls via `FactoriesService.clnCall(...)`:")
md.append("")

wallet_used = [
    "factory-list", "factory-create", "factory-rotate", "factory-close",
    "factory-force-close", "factory-trigger-ceremony", "factory-open-channels",
    "factory-browse-host", "factory-join-request", "factory-cancel-join",
    "factory-approve-proposal", "factory-refuse-proposal", "factory-review-proposal",
    "factory-check-breach", "factory-get-cached-policy",
    "client-list-held-proposals", "client-list-recent-sign-queue-events",
    "client-dismiss-sign-queue-event", "client-signing-prefs-get", "client-signing-prefs-set",
    "wallet-list-known-peers", "wallet-set-peer-note", "wallet-get-peer-note",
    "wallet-set-peer-reputation", "wallet-get-peer-reputation",
    "wallet-list-join-queue-by-status", "wallet-count-join-queue-by-status",
    "wallet-approve-join-queued", "wallet-refuse-join-queued",
    "wallet-set-operator-pref", "wallet-get-operator-pref",
    "wallet-list-events-since", "wallet-get-latest-event-id",
]
md.append("- " + "\n- ".join(f"`{r}`" for r in wallet_used))
md.append("")
md.append(f"({len(wallet_used)} of the {sum(len(v) for v in categories.values())} total RPCs are surfaced in the wallet UI.)")
md.append("")

out_path = "/root/superscalar-cln/SUPERSCALAR_RPC_SPEC.md"
with open(out_path, "w") as f:
    f.write("\n".join(md) + "\n")
print(f"Wrote {out_path} ({len(md)} lines)")
for prefix, entries in categories.items():
    print(f"  {prefix}: {len(entries)} RPCs")
