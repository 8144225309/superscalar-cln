/* Phase 4d2: P2TR key-path sweep TX builder.
 *
 * Ports upstream SuperScalar's build_p2tr_keypath_sweep (sweeper.c:34)
 * with a hex-returning wrapper suitable for CLN's sendrawtransaction
 * RPC. Used to claim factory-level P2TR outputs (LSP stock share from
 * distribution TX, leaf outputs, post-timeout-spend forwarding) to a
 * wallet-owned destination.
 *
 * This does NOT handle script-path spends (to_local CSV, HTLC timeout
 * scripts). The factory-level sweep destinations our plugin produces
 * all use plain P2TR key-path encoding — output_key =
 * TapTweak(internal_xonly, empty) — so key-path-only coverage is
 * sufficient for SWEEP_TYPE_FACTORY_LSTOCK, FACTORY_LEAF, and
 * FACTORY_TIMEOUT.
 */
#ifndef SUPERSCALAR_PLUGIN_SWEEP_BUILDER_H
#define SUPERSCALAR_PLUGIN_SWEEP_BUILDER_H

#include <stddef.h>
#include <stdint.h>

/* Build a signed P2TR key-path sweep of a single input.
 *
 * On success, returns a malloc()'d hex string (NUL-terminated) that can
 * be passed to bitcoind's sendrawtransaction. Caller owns the memory
 * and must free() it.
 *
 * Returns NULL on failure (uneconomical amount, sign error, internal
 * build error). Failure reason is logged via stderr at LOG_UNUSUAL-ish
 * verbosity; callers should treat NULL as "this sweep cannot be built
 * right now" and retry later or mark FAILED.
 *
 * Arguments:
 *   source_txid32     — 32-byte internal-order (little-endian RPC) txid
 *                       of the UTXO we are spending.
 *   source_vout       — Output index in source_txid32.
 *   source_amount     — Value of the source output in sats.
 *   internal_secret32 — 32-byte secret key for the internal x-only
 *                       pubkey that (after BIP-341 empty TapTweak)
 *                       produced the source output's key.
 *   dest_spk / len    — Destination scriptPubKey bytes (typically a
 *                       P2TR or P2WPKH address returned by CLN newaddr).
 *   fee_per_kvb       — Fee rate in sat/kvB applied to a 112-vB estimate
 *                       for the key-path spend.
 */
char *ss_build_p2tr_keypath_sweep_hex(
	const uint8_t *source_txid32,
	uint32_t source_vout,
	uint64_t source_amount,
	const uint8_t *internal_secret32,
	const uint8_t *dest_spk,
	size_t dest_spk_len,
	uint64_t fee_per_kvb,
	uint8_t sweep_txid_out[32]);

#endif
