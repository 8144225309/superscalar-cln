/* Factory instance state management for the SuperScalar CLN plugin.
 *
 * Each factory_instance tracks:
 * - Participants (LSP + N clients)
 * - DW tree state via libsuperscalar
 * - MuSig2 ceremony progress
 * - Channel-to-leaf mappings
 * - Lifecycle (active/dying/expired)
 * - Breach/penalty data per epoch
 */
#ifndef SUPERSCALAR_FACTORY_STATE_H
#define SUPERSCALAR_FACTORY_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ceremony.h"

/* Max participants in a single factory (LSP + clients) */
#define MAX_FACTORY_PARTICIPANTS 16

/* Max nonce entries (must match nonce_exchange.h) */
#ifndef MAX_NONCE_ENTRIES
#define MAX_NONCE_ENTRIES 256
#endif

/* Max concurrent factories */
#define MAX_FACTORIES 32

/* Factory lifecycle */
typedef enum {
	FACTORY_LIFECYCLE_INIT,		/* Being created, ceremony in progress */
	FACTORY_LIFECYCLE_ACTIVE,	/* Signed tree, channels open */
	FACTORY_LIFECYCLE_DYING,	/* Close initiated or timelock approaching */
	FACTORY_LIFECYCLE_EXPIRED,	/* Closed on-chain, all settled */
} factory_lifecycle_t;

/* Per-epoch breach data */
typedef struct {
	uint32_t epoch;
	uint8_t revocation_secret[32];	/* Secret for this epoch */
	bool has_revocation;		/* Whether we have the secret */
	/* Serialized commitment txs per leaf — needed for penalty */
	uint8_t *commitment_data;
	size_t commitment_data_len;
} epoch_breach_data_t;

/* Channel-to-leaf mapping */
typedef struct {
	uint8_t channel_id[32];		/* CLN channel_id */
	int leaf_index;			/* Index into factory tree */
	int leaf_side;			/* 0=A (client), 1=B (LSP L-stock) */
} channel_leaf_map_t;

/* Per-client ceremony tracking */
typedef struct {
	uint8_t node_id[33];		/* Compressed pubkey */
	bool connected;			/* Currently connected */
	bool nonce_received;		/* Sent NONCE_BUNDLE this round */
	bool psig_received;		/* Sent PSIG_BUNDLE this round */
	int signer_slot;		/* Index in MuSig2 signer set */
} client_state_t;

/* Factory instance */
typedef struct factory_instance {
	/* Identity */
	uint8_t instance_id[32];
	uint8_t protocol_id[32];

	/* Role */
	bool is_lsp;			/* Are we the LSP for this factory? */

	/* Participants */
	uint8_t lsp_node_id[33];
	client_state_t clients[MAX_FACTORY_PARTICIPANTS];
	size_t n_clients;

	/* Ceremony */
	ceremony_state_t ceremony;
	uint32_t ceremony_round;	/* Which round of nonce/sig exchange */

	/* DW state */
	uint32_t epoch;			/* Current DW epoch */
	uint32_t max_epochs;		/* Total states before exhaustion */

	/* Lifecycle */
	factory_lifecycle_t lifecycle;
	uint32_t creation_block;	/* Block height at creation */
	uint32_t expiry_block;		/* Absolute block height of factory expiry */
	uint16_t early_warning_time;	/* Blocks before expiry to warn */

	/* Channel mappings */
	channel_leaf_map_t channels[MAX_FACTORY_PARTICIPANTS];
	size_t n_channels;

	/* Breach data (circular buffer of recent epochs) */
	epoch_breach_data_t *breach_data;
	size_t n_breach_epochs;

	/* Rotation */
	bool rotation_in_progress;

	/* Funding info */
	uint8_t funding_txid[32];
	uint32_t funding_outnum;

	/* Handle to libsuperscalar factory_t.
	 * NULL until the library is initialized for this instance.
	 * Declared as void* to avoid requiring superscalar headers
	 * in every file that includes factory_state.h. */
	void *lib_factory;

	/* MuSig2 nonce pool (heap-allocated, secnonces live inside) */
	void *nonce_pool;
	/* Per-entry: which pool index maps to which tree node */
	uint32_t secnonce_node_idx[MAX_NONCE_ENTRIES];
	uint32_t secnonce_pool_idx[MAX_NONCE_ENTRIES];
	size_t n_secnonces;
	uint8_t our_seckey[32];
	int our_participant_idx;

} factory_instance_t;

/* Global plugin state */
typedef struct superscalar_state {
	factory_instance_t *factories[MAX_FACTORIES];
	size_t n_factories;
	bool is_lsp;			/* Global mode: LSP or client */
	uint8_t our_node_id[33];	/* Our compressed pubkey */
	uint32_t current_blockheight;
} superscalar_state_t;

/* State management functions */

/* Initialize global state */
void ss_state_init(superscalar_state_t *state);

/* Create a new factory instance */
factory_instance_t *ss_factory_new(superscalar_state_t *state,
				   const uint8_t *instance_id);

/* Find factory by instance_id */
factory_instance_t *ss_factory_find(superscalar_state_t *state,
				    const uint8_t *instance_id);

/* Find factory by channel_id (searches channel mappings) */
factory_instance_t *ss_factory_find_by_channel(superscalar_state_t *state,
					       const uint8_t *channel_id);

/* Find client within a factory by node_id */
client_state_t *ss_factory_find_client(factory_instance_t *fi,
				       const uint8_t *node_id);

/* Check if all clients have sent nonces for current round */
bool ss_factory_all_nonces_received(const factory_instance_t *fi);

/* Check if all clients have sent partial sigs for current round */
bool ss_factory_all_psigs_received(const factory_instance_t *fi);

/* Reset ceremony tracking for a new round */
void ss_factory_reset_ceremony(factory_instance_t *fi);

/* Add breach data for an epoch */
void ss_factory_add_breach_data(factory_instance_t *fi,
				uint32_t epoch,
				const uint8_t *revocation_secret,
				const uint8_t *commitment_data,
				size_t commitment_data_len);

/* Map a CLN channel to a factory leaf */
void ss_factory_map_channel(factory_instance_t *fi,
			    const uint8_t *channel_id,
			    int leaf_index, int leaf_side);

/* Lifecycle checks */
bool ss_factory_should_warn(const factory_instance_t *fi,
			    uint32_t current_block);
bool ss_factory_should_close(const factory_instance_t *fi,
			     uint32_t current_block);

#endif /* SUPERSCALAR_FACTORY_STATE_H */
