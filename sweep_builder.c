/* Phase 4d2: P2TR key-path sweep TX builder — see sweep_builder.h.
 *
 * Implementation is a trimmed-down port of upstream SuperScalar's
 * build_p2tr_keypath_sweep (sweeper.c:34). We pull in the upstream
 * headers for tx_builder + sha256_tagged helpers (those .o files are
 * already in libsuperscalar_slim per build-plugin.sh).
 */
#include "sweep_builder.h"

#include <superscalar/channel.h>   /* CHANNEL_DUST_LIMIT_SATS */
#include <superscalar/tx_builder.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* build-plugin.sh renames the utility symbols that collide with CLN
 * (sha256_tagged → ss_sha256_tagged, etc.) in the slim archive. Use
 * the renamed symbols directly here — our .c is not run through the
 * objcopy rename step. */
extern void ss_sha256_tagged(const char *tag, const unsigned char *data,
			     size_t data_len, unsigned char out[32]);

char *ss_build_p2tr_keypath_sweep_hex(
	secp256k1_context *ctx,
	const uint8_t *source_txid32,
	uint32_t source_vout,
	uint64_t source_amount,
	const uint8_t *internal_secret32,
	const uint8_t *dest_spk,
	size_t dest_spk_len,
	uint64_t fee_per_kvb,
	uint8_t sweep_txid_out[32])
{
	if (!source_txid32 || !internal_secret32 || !dest_spk || !ctx)
		return NULL;
	if (dest_spk_len == 0 || dest_spk_len > sizeof(((tx_output_t *)0)->script_pubkey))
		return NULL;

	/* Key-path P2TR spend: ~112 vB (1-in key-path, 1-out) — same
	 * estimate as upstream sweeper.c. */
	uint64_t vsize = 112;
	uint64_t fee = (fee_per_kvb * vsize + 999) / 1000;
	if (source_amount <= fee + CHANNEL_DUST_LIMIT_SATS)
		return NULL;
	uint64_t out_amount = source_amount - fee;

	tx_output_t output;
	memset(&output, 0, sizeof(output));
	memcpy(output.script_pubkey, dest_spk, dest_spk_len);
	output.script_pubkey_len = dest_spk_len;
	output.amount_sats = out_amount;

	/* Derive the internal xonly pubkey from the secret. */
	secp256k1_keypair kp;
	if (!secp256k1_keypair_create(ctx, &kp, internal_secret32))
		return NULL;

	secp256k1_xonly_pubkey internal_xonly;
	int parity = 0;
	if (!secp256k1_keypair_xonly_pub(ctx, &internal_xonly,
					 &parity, &kp)) {
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}

	uint8_t internal_ser[32];
	if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser,
					      &internal_xonly)) {
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}

	/* BIP-341 TapTweak with no script root (empty). */
	uint8_t tweak[32];
	ss_sha256_tagged("TapTweak", internal_ser, 32, tweak);

	/* Tweak the signing keypair in place. */
	if (!secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak)) {
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}

	/* Reconstruct the source SPK. After the tweak, the keypair's
	 * xonly pubkey is the output key; its 32-byte serialization sits
	 * after 0x51 0x20 in the source scriptPubKey. */
	secp256k1_xonly_pubkey output_xonly;
	if (!secp256k1_keypair_xonly_pub(ctx, &output_xonly,
					 &parity, &kp)) {
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}
	uint8_t source_spk[34];
	build_p2tr_script_pubkey(source_spk, &output_xonly);

	/* Unsigned TX: single input, single output, nSequence=0xFFFFFFFD
	 * (RBF-signaling, matches upstream sweeper.c). */
	tx_buf_t unsigned_tx;
	tx_buf_init(&unsigned_tx, 256);
	uint8_t txid[32];
	if (!build_unsigned_tx_v(&unsigned_tx, txid,
				 source_txid32, source_vout,
				 0xFFFFFFFD, &output, 1, 2)) {
		tx_buf_free(&unsigned_tx);
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}

	/* Taproot key-path sighash + Schnorr sign. */
	uint8_t sighash[32];
	if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
				     0, source_spk, 34,
				     source_amount, 0xFFFFFFFD)) {
		tx_buf_free(&unsigned_tx);
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}

	uint8_t sig[64];
	if (!secp256k1_schnorrsig_sign32(ctx, sig, sighash, &kp, NULL)) {
		tx_buf_free(&unsigned_tx);
		memset(&kp, 0, sizeof(kp));
		return NULL;
	}
	memset(&kp, 0, sizeof(kp));

	tx_buf_t signed_tx;
	tx_buf_init(&signed_tx, 256);
	if (!finalize_signed_tx(&signed_tx, unsigned_tx.data, unsigned_tx.len, sig)) {
		tx_buf_free(&unsigned_tx);
		tx_buf_free(&signed_tx);
		return NULL;
	}
	tx_buf_free(&unsigned_tx);

	/* build_unsigned_tx_v stashed the non-witness txid for us; that is
	 * the wtxid-invariant segwit txid Bitcoin Core will return from
	 * sendrawtransaction. */
	if (sweep_txid_out)
		memcpy(sweep_txid_out, txid, 32);

	char *hex = malloc(signed_tx.len * 2 + 1);
	if (!hex) {
		tx_buf_free(&signed_tx);
		return NULL;
	}
	for (size_t i = 0; i < signed_tx.len; i++)
		sprintf(hex + i*2, "%02x", signed_tx.data[i]);
	hex[signed_tx.len * 2] = '\0';
	tx_buf_free(&signed_tx);
	return hex;
}
