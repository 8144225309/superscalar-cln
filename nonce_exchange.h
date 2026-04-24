/* Nonce exchange helpers for factory ceremony.
 *
 * Serialization format for FACTORY_PROPOSE nonce bundle:
 *   [32 bytes: factory_instance_id]
 *   [4 bytes: n_participants]
 *   [4 bytes: n_nodes]
 *   [4 bytes: n_entries]
 *   For each entry:
 *     [4 bytes: node_idx]
 *     [4 bytes: signer_slot]
 *     [66 bytes: serialized pubnonce]
 *
 * Same format for NONCE_BUNDLE response (client → LSP).
 */
#ifndef SUPERSCALAR_NONCE_EXCHANGE_H
#define SUPERSCALAR_NONCE_EXCHANGE_H

#include <stdint.h>
#include <stddef.h>

/* Max entries in a nonce bundle (n_nodes * n_signers).
 * nonce_bundle_t must be heap-allocated when MAX_NONCE_ENTRIES is large.
 * 1024 supports factories with up to ~256 nodes × 4 signers.
 * (4-party DW factory with states_per_layer=16 generates ~256 nodes) */
#define MAX_NONCE_ENTRIES 1024

typedef struct {
	uint32_t node_idx;
	uint32_t signer_slot;
	uint8_t pubnonce[66];
} nonce_entry_t;

/* Max participants — matches FACTORY_MAX_SIGNERS in libsuperscalar v0.1.9. */
#define MAX_PARTICIPANTS 64

typedef struct {
	uint8_t instance_id[32];
	uint32_t n_participants;
	uint32_t n_nodes;
	/* Compressed pubkeys for all participants (33 bytes each) */
	uint8_t pubkeys[MAX_PARTICIPANTS][33];
	nonce_entry_t entries[MAX_NONCE_ENTRIES];
	size_t n_entries;

	/* Funding UTXO info (populated in ALL_NONCES by LSP, zeroed otherwise).
	 * funding_spk_len > 0 indicates real funding data is present. */
	uint8_t  funding_txid[32];
	uint32_t funding_vout;
	uint64_t funding_amount_sats;
	uint8_t  funding_spk[34];
	uint8_t  funding_spk_len;

	/* Tier 2.6: arity policy. 0 = auto (receiver uses ss_choose_arity on
	 * n_participants). 1/2/3 map to libsuperscalar FACTORY_ARITY_1/2/PS.
	 * Added as an optional trailer after the funding section for backward
	 * compat — peers that don't send it effectively request "auto". */
	uint8_t  arity_mode;
} nonce_bundle_t;

/* Serialize nonce bundle to binary */
size_t nonce_bundle_serialize(const nonce_bundle_t *nb,
			      uint8_t *out, size_t out_max);

/* Deserialize nonce bundle from binary */
int nonce_bundle_deserialize(nonce_bundle_t *nb,
			     const uint8_t *data, size_t len);

#endif /* SUPERSCALAR_NONCE_EXCHANGE_H */
