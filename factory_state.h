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
#include "nonce_exchange.h"

/* Max participants in a single factory (LSP + clients).
 * Matches FACTORY_MAX_SIGNERS in libsuperscalar v0.1.9. */
#define MAX_FACTORY_PARTICIPANTS 64

/* Max concurrent factories */
#define MAX_FACTORIES 32

/* Factory lifecycle.
 *
 * States 0-3 (INIT/ACTIVE/DYING/EXPIRED) are the original state machine driven
 * by the ceremony + force-close pathways.
 *
 * States 4-7 are terminal-closed states set by the watcher (Phase 1+ of the
 * trustless-watcher plan). Only CLOSED_EXTERNALLY is populated by Phase 1; the
 * remaining closed-* values are reserved so the persistence format stabilizes
 * in one go and Phase 2's classifier can populate them without another version
 * bump. Factories in any closed-* state are skipped by the breach scan and the
 * ceremony paths, and are safe to reap via factory-confirm-closed.
 *
 * Do not renumber — enum values are serialized as u8 in persist.c. */
typedef enum {
	FACTORY_LIFECYCLE_INIT = 0,		/* Being created, ceremony in progress */
	FACTORY_LIFECYCLE_ACTIVE = 1,		/* Signed tree, channels open */
	FACTORY_LIFECYCLE_DYING = 2,		/* Close initiated or timelock approaching */
	FACTORY_LIFECYCLE_EXPIRED = 3,		/* nLockTime distribution TX path */

	/* Watcher-populated terminal states (Phase 1+). */
	FACTORY_LIFECYCLE_CLOSED_EXTERNALLY = 4, /* Root spent outside plugin
						  * control (manual sweep, HSM-
						  * lost recovery, etc.). Set by
						  * the UTXO heartbeat in
						  * breach_utxo_checked when the
						  * factory was ACTIVE (i.e. we
						  * didn't initiate the close). */
	FACTORY_LIFECYCLE_CLOSED_COOPERATIVE = 5, /* Reserved — Phase 2 */
	FACTORY_LIFECYCLE_CLOSED_UNILATERAL = 6,  /* Reserved — Phase 2 */
	FACTORY_LIFECYCLE_CLOSED_BREACHED = 7,    /* Reserved — Phase 2+3 */
} factory_lifecycle_t;

/* Helper: a factory in any closed terminal state should not be scanned,
 * advertised, or rotated. Centralizes the state check so Phase 2's classifier
 * can add new closed states without hunting down every gate. */
static inline bool factory_is_closed(factory_lifecycle_t l) {
	return l == FACTORY_LIFECYCLE_EXPIRED
	    || l == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY
	    || l == FACTORY_LIFECYCLE_CLOSED_COOPERATIVE
	    || l == FACTORY_LIFECYCLE_CLOSED_UNILATERAL
	    || l == FACTORY_LIFECYCLE_CLOSED_BREACHED;
}

/* Phase 2a: values for factory_instance_t.closed_by. Stored as uint8_t
 * in persistence; do not renumber without a meta-version bump. */
#define CLOSED_BY_UNKNOWN       0 /* haven't classified, or scan found nothing */
#define CLOSED_BY_SELF          1 /* our dist_tx or our kickoff matched */
#define CLOSED_BY_COUNTERPARTY  2 /* scan found a TX we didn't sign — Phase 2b
				   * refines into normal-exit vs. breach */

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
	uint8_t factory_pubkey[33];	/* Real factory pubkey (from NONCE_BUNDLE) */
	bool has_factory_pubkey;	/* Whether factory_pubkey was received */
	uint64_t allocation_sats;	/* Sats allocated to this client's channel.
					 * 0 = use default even-split. Set by
					 * factory-create `allocations` param. */
	/* REVOKE delivery tracking (LSP-side only).
	 *
	 *   pending_revoke_epoch — epoch whose secret we sent REVOKE for
	 *                          and are still waiting on REVOKE_ACK.
	 *                          UINT32_MAX when nothing is pending.
	 *   last_acked_epoch     — highest epoch this client has acked.
	 *                          UINT32_MAX when no ack has ever been
	 *                          received (pre-rotation factories).
	 *
	 * The rotation path consults these before sending the NEXT REVOKE
	 * so we never race ahead of a client whose storage write is in
	 * flight or whose peer connection is flapping. Both fields are
	 * persisted in meta. On reconnect, any pending_revoke_epoch that
	 * hasn't been acked triggers a REVOKE resend. */
	uint32_t pending_revoke_epoch;
	uint32_t last_acked_epoch;
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

	/* HTLC early-warning: set true the first time handle_block_added
	 * sees ss_factory_should_warn() fire and triggers force-closes on
	 * this factory's LN channels. Prevents repeated close RPCs on
	 * subsequent blocks while the close is in flight / settling. Not
	 * persisted on purpose — if the plugin restarts inside the early-
	 * warning window, we want to re-trigger closes for any channels
	 * that hadn't completed closing yet. */
	bool warning_close_triggered;

	/* Key turnover (assisted exit): per-client departure state.
	 * When a client departs, we store their extracted secret key
	 * so the LSP can sign on their behalf for the factory's lifetime. */
	bool client_departed[MAX_FACTORY_PARTICIPANTS];
	uint8_t extracted_keys[MAX_FACTORY_PARTICIPANTS][32];
	size_t n_departed;

	/* Funding info */
	uint8_t funding_txid[32];
	uint32_t funding_outnum;
	uint64_t funding_amount_sats;
	uint8_t funding_spk[34];
	uint8_t funding_spk_len;

	/* Block height at which the watcher observed the funding root spent
	 * outside plugin control. 0 for factories that never hit
	 * CLOSED_EXTERNALLY. Persisted in meta v6+ so operator tooling can
	 * show "zombie since block N" and forensics can line up with chain
	 * history. */
	uint32_t closed_externally_at_block;

	/* Phase 2a: spending-TX identification.
	 *
	 * Populated by the block scan launched after the UTXO heartbeat
	 * detects the funding root spent. The scan walks recent blocks
	 * looking for a TX whose vin references our funding outpoint; once
	 * found, we match its txid against our own signed artifacts
	 * (dist_signed_tx for cooperative, lib_factory->nodes[0].txid for
	 * our unilateral kickoff) and set lifecycle/closed_by accordingly.
	 *
	 * When the scan fails to find the spending TX (the spend predates
	 * our scan window), spending_txid stays all-zero and classification
	 * remains CLOSED_EXTERNALLY with closed_by = CLOSED_BY_UNKNOWN.
	 *
	 * Phase 2b will add per-epoch tree reconstruction to distinguish
	 * counterparty-normal-exit from breach within the
	 * "closed_by != self" bucket. */
	uint8_t spending_txid[32];
	uint32_t first_noticed_block; /* block_added height when UTXO was first seen spent */

	/* Who drove the close, per Phase 2a classification. Values match the
	 * CLOSED_BY_* constants below. Stored as uint8_t for portable
	 * persistence; don't renumber the constants without a version bump. */
	uint8_t closed_by;

	/* Phase 2b: cooperative-close identification.
	 *
	 * When dist_signed_tx is set (distribution TX is MuSig2-signed and
	 * ready to broadcast), we precompute its segwit txid (BIP-141
	 * non-witness serialization, double-SHA256) and cache here. The
	 * classifier matches spending_txid against this value to recognize
	 * "factory was cooperatively closed" — could be either party that
	 * actually broadcast; same signed bytes, same txid either way.
	 * All-zero means no dist TX is signed yet. */
	uint8_t dist_signed_txid[32];

	/* Phase 2b: breach-epoch identification.
	 *
	 * When the classifier matches the spending TX's witness signature
	 * to a past epoch's kickoff signature, this records which epoch
	 * the counterparty published. Only meaningful when
	 * lifecycle == FACTORY_LIFECYCLE_CLOSED_BREACHED. UINT32_MAX sentinel
	 * when no breach has been classified. Phase 3 reads this to pick
	 * the right revocation secret when building the penalty TX. */
	uint32_t breach_epoch;

	/* Phase 2b: per-epoch kickoff witness signature cache.
	 *
	 * The kickoff TXID is stable across epochs (DW timelock race requires
	 * it — see the comment in json_factory_rotate) but the WITNESS
	 * (Schnorr signature) differs per epoch because MuSig2 signs the
	 * input with a per-epoch-aggregated key state. So matching a
	 * published kickoff against stored per-epoch witnesses tells us
	 * which epoch the counterparty broadcast.
	 *
	 * history_kickoff_sigs[i] holds the 64-byte Schnorr sig captured at
	 * the moment we rotated past epoch (history_kickoff_epochs[i]). Both
	 * LSP and client capture independently; signatures are identical
	 * because MuSig2 aggregation is deterministic. Capped at the max
	 * rotation count (16 per current default); grows monotonically.
	 *
	 * Factories that existed before Phase 2b shipped start with
	 * n_history_kickoff_sigs = 0 and can't be classified via sig match
	 * for any past epoch; the classifier falls back to
	 * closed_by=COUNTERPARTY without an epoch label. */
	#define MAX_HISTORY_SIGS 64
	uint8_t history_kickoff_sigs[MAX_HISTORY_SIGS][64];
	uint32_t history_kickoff_epochs[MAX_HISTORY_SIGS];
	size_t n_history_kickoff_sigs;

	/* Cached tree node count (persisted so factory-list works after restart
	 * even when lib_factory hasn't been rebuilt yet). */
	uint32_t n_tree_nodes;

	/* Signed distribution TX (nLockTime fallback).
	 * Broadcast after factory expiry — clients get their funds. */
	uint8_t *dist_signed_tx;
	size_t dist_signed_tx_len;

	/* Handle to libsuperscalar factory_t.
	 * NULL until the library is initialized for this instance.
	 * Declared as void* to avoid requiring superscalar headers
	 * in every file that includes factory_state.h. */
	void *lib_factory;

	/* Distribution TX standalone MuSig2 signing session.
	 * Separate from tree node sessions — uses root keyagg. */
	void *dist_session;  /* musig_signing_session_t* */

	/* Cached nonce entries for ALL_NONCES broadcast (multi-client).
	 * Populated during FACTORY_PROPOSE (LSP's own nonces) and
	 * NONCE_BUNDLE (each client's nonces). Sent as ALL_NONCES
	 * when all clients have responded. Heap-allocated. */
	void *cached_nonces;     /* nonce_entry_t* array */
	size_t n_cached_nonces;
	size_t cached_nonces_cap;

	/* Cached serialized ALL_NONCES wire payload for reconnect recovery.
	 * Populated when ALL_NONCES is first sent; freed after PSIG phase.
	 * Allows re-sending ALL_NONCES if a client disconnects mid-ceremony. */
	uint8_t *cached_all_nonces_wire;
	size_t cached_all_nonces_len;

	/* MuSig2 nonce pool (heap-allocated, secnonces live inside) */
	void *nonce_pool;
	/* Per-entry: which pool index maps to which tree node */
	uint32_t secnonce_node_idx[MAX_NONCE_ENTRIES];
	uint32_t secnonce_pool_idx[MAX_NONCE_ENTRIES];
	size_t n_secnonces;
	uint8_t our_seckey[32];
	int our_participant_idx;

	/* Per-client allocations (sats). Index 0 = client 0, index 1 = client 1...
	 * Populated on LSP from factory-create `allocations` param, and on
	 * clients from FACTORY_PROPOSE / ALL_NONCES payloads.
	 * n_allocations == 0 means fall back to even split. */
	uint8_t n_allocations;
	uint64_t allocations[MAX_FACTORY_PARTICIPANTS];

} factory_instance_t;

/* Global plugin state */
typedef struct superscalar_state {
	factory_instance_t *factories[MAX_FACTORIES];
	size_t n_factories;
	bool is_lsp;			/* Global mode: LSP or client */
	uint8_t our_node_id[33];	/* Our compressed pubkey */
	uint32_t current_blockheight;
	uint8_t factory_master_key[32];	/* HSM-derived master key for factories */
	bool has_master_key;		/* Whether master key was derived */
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
