/* Factory ceremony coordination for the SuperScalar CLN plugin.
 *
 * Maps SuperScalar's multi-party MuSig2 signing protocol to
 * bLIP-56 factory submessages tunneled through CLN.
 *
 * Factory creation ceremony (3 rounds):
 *   Round 1: LSP builds tree, generates nonces, sends NONCE_BUNDLE
 *   Round 2: Clients return nonces, LSP aggregates, sends ALL_NONCES
 *   Round 3: Clients return partial sigs, LSP aggregates → signed tree
 *
 * Wire submessage IDs (SuperScalar-specific, above bLIP-56 range):
 *   0x0100 = FACTORY_PROPOSE (tree params + funding)
 *   0x0101 = NONCE_BUNDLE (per-signer nonce set)
 *   0x0102 = ALL_NONCES (aggregated nonces for all nodes)
 *   0x0103 = PSIG_BUNDLE (per-signer partial sig set)
 *   0x0104 = FACTORY_READY (signed tree, channel params)
 *   0x0110 = CLOSE_PROPOSE
 *   0x0111 = CLOSE_NONCE
 *   0x0112 = CLOSE_ALL_NONCES
 *   0x0113 = CLOSE_PSIG
 *   0x0114 = CLOSE_DONE
 */
#ifndef SUPERSCALAR_CEREMONY_H
#define SUPERSCALAR_CEREMONY_H

#include <stdint.h>
#include <stddef.h>

/* Factory submessage IDs — SuperScalar protocol messages
 * carried inside bLIP-56 factory_message (32800) */
#define SS_SUBMSG_FACTORY_PROPOSE	0x0100
#define SS_SUBMSG_NONCE_BUNDLE		0x0101
#define SS_SUBMSG_ALL_NONCES		0x0102
#define SS_SUBMSG_PSIG_BUNDLE		0x0103
#define SS_SUBMSG_FACTORY_READY		0x0104
#define SS_SUBMSG_CLOSE_PROPOSE		0x0110
#define SS_SUBMSG_CLOSE_NONCE		0x0111
#define SS_SUBMSG_CLOSE_ALL_NONCES	0x0112
#define SS_SUBMSG_CLOSE_PSIG		0x0113
#define SS_SUBMSG_CLOSE_DONE		0x0114

/* Ceremony state for a factory creation in progress */
typedef enum {
	CEREMONY_IDLE,
	CEREMONY_PROPOSED,	/* Sent FACTORY_PROPOSE, waiting for nonces */
	CEREMONY_NONCES_COLLECTED,  /* All nonces received, sent ALL_NONCES */
	CEREMONY_PSIGS_COLLECTED,   /* All partial sigs received */
	CEREMONY_COMPLETE,	/* Factory tree fully signed */
	CEREMONY_FAILED,
} ceremony_state_t;

#endif /* SUPERSCALAR_CEREMONY_H */
