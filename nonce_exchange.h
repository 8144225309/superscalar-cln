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
 * Raised for v0.1.9 (256 nodes * 64 signers possible). */
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
} nonce_bundle_t;

/* Serialize nonce bundle to binary */
size_t nonce_bundle_serialize(const nonce_bundle_t *nb,
			      uint8_t *out, size_t out_max);

/* Deserialize nonce bundle from binary */
int nonce_bundle_deserialize(nonce_bundle_t *nb,
			     const uint8_t *data, size_t len);

#endif /* SUPERSCALAR_NONCE_EXCHANGE_H */
