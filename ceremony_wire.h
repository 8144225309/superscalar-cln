/* Wire codec for the trigger-ceremony submsgs (0x0145-0x014C).
 *
 * These submsgs implement the create-then-trigger ceremony model
 * defined in CEREMONY_DESIGN.md §5. They carry the sequencing-safety
 * fields (ceremony_id, parent_ceremony_id, deadline_block) that the
 * older inline-clients factory_create flow (0x0100-0x0114) lacks.
 *
 * The two protocols coexist during the v1 → v2 transition; the older
 * submsgs remain in use for the synchronous factory-create code path
 * until PR 10 of the ceremony roadmap removes them.
 *
 * Wire format conventions:
 *   - Multi-byte integers are big-endian (matches existing codec style).
 *   - ceremony_id is 8 random bytes (from /dev/urandom via
 *     ss_fresh_request_id-style helper). All-zero parent_ceremony_id
 *     means "this is the first ceremony after factory creation."
 *   - MuSig2 public nonces are 66 bytes (two 33-byte points R1 || R2).
 *   - Aggregated Schnorr signatures are 64 bytes (BIP-340 form).
 *   - Variable-length fields carry a u16 BE length prefix.
 */
#ifndef SUPERSCALAR_CEREMONY_WIRE_H
#define SUPERSCALAR_CEREMONY_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ------------------------------------------------------------------
 * Submsg IDs (defined in ceremony.h alongside the existing
 * 0x0100-0x0144 range)
 * ------------------------------------------------------------------ */

#define SS_SUBMSG_CEREMONY_START          0x0145
#define SS_SUBMSG_CEREMONY_NONCE_REPLY    0x0146
#define SS_SUBMSG_CEREMONY_PARTIAL_SIG_REQ 0x0147
#define SS_SUBMSG_CEREMONY_PARTIAL_SIG    0x0148
#define SS_SUBMSG_CEREMONY_RESULT         0x0149
#define SS_SUBMSG_CEREMONY_ABORT          0x014A
#define SS_SUBMSG_CEREMONY_STATUS_QUERY   0x014B
#define SS_SUBMSG_CEREMONY_STATUS_REPLY   0x014C

/* ------------------------------------------------------------------
 * Signing-availability protocol — client reconnect pull.
 * On reconnect a client sends SIGN_QUEUE_REQUEST to ask the LSP for
 * any ceremonies it was missed during disconnect; the LSP replies with
 * SIGN_QUEUE_RESPONSE listing the pending proposals so the client can
 * resume signing. FACTORY_PROPOSE_V2 carries a policy-diff trailer
 * (used when the LSP re-issues a proposal whose policy has changed).
 * ------------------------------------------------------------------ */
#define SS_SUBMSG_SIGN_QUEUE_REQUEST      0x014D  /* client -> LSP */
#define SS_SUBMSG_SIGN_QUEUE_RESPONSE     0x014E  /* LSP -> client */
#define SS_SUBMSG_FACTORY_PROPOSE_V2      0x014F  /* LSP -> client; carries policy diff trailer (Phase C v2) */

/* CEREMONY_ABORT reason codes (one byte payload, audit item #3) */
#define SS_CEREMONY_ABORT_USER_REFUSED      0  /* client refused via factory-refuse-proposal */
#define SS_CEREMONY_ABORT_POLICY_VIOLATED   1  /* validator rejected the proposal */
#define SS_CEREMONY_ABORT_DEADLINE_PASSED   2  /* client missed deadline window */
#define SS_CEREMONY_ABORT_OTHER             3  /* unspecified */

/* States for an LSP's per-client signature queue entry.  Carried in
 * the SIGN_QUEUE_RESPONSE state TLV (0x02). */
#define SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE  0
#define SS_SIGQUEUE_SIGNED                   1
#define SS_SIGQUEUE_MISSED                   2
#define SS_SIGQUEUE_REFUSED                  3
#define SS_SIGQUEUE_EXPIRED                  4

/* ------------------------------------------------------------------
 * Ceremony type byte (carried inside CEREMONY_START)
 * Per CEREMONY_DESIGN.md §4.1. 0x09 (former PENALTY_BURN) is reserved
 * unused per lib-team correction (2026-05-18).
 * ------------------------------------------------------------------ */

#define SS_CEREMONY_TYPE_INITIAL              0x01
#define SS_CEREMONY_TYPE_ROTATE               0x02
#define SS_CEREMONY_TYPE_JOIN                 0x03  /* v2 reserved */
#define SS_CEREMONY_TYPE_LEAVE                0x04  /* v2 reserved */
#define SS_CEREMONY_TYPE_FORCE_OUT            0x05
#define SS_CEREMONY_TYPE_CLOSE                0x06  /* v2 reserved */
#define SS_CEREMONY_TYPE_DISTRIBUTION_UPDATE  0x07  /* v2 reserved */
#define SS_CEREMONY_TYPE_STATE_UPDATE         0x08  /* v2 reserved */
#define SS_CEREMONY_TYPE_RESERVED_PENALTY_BURN 0x09 /* reserved unused; see CEREMONY_DESIGN.md §4.6 */
#define SS_CEREMONY_TYPE_ABORT                0x0A

/* ------------------------------------------------------------------
 * Refuse codes (carried inside CEREMONY_NONCE_REPLY when participant
 * declines to sign). 0x00 means "no refusal; nonce reply follows."
 * ------------------------------------------------------------------ */

#define SS_REFUSE_NONE                    0x00  /* no refusal; nonce follows */
#define SS_REFUSE_UNKNOWN_FACTORY         0x01
#define SS_REFUSE_POLICY_VIOLATION_TX     0x02
#define SS_REFUSE_POLICY_VIOLATION_ALLOC  0x03
#define SS_REFUSE_SEQUENCING_VIOLATION    0x04
#define SS_REFUSE_TEMPORARY_UNAVAILABLE   0x05
#define SS_REFUSE_USER_DECLINED           0x06
#define SS_REFUSE_UNSPECIFIED             0xFF

/* ------------------------------------------------------------------
 * Abort reason codes (carried inside CEREMONY_ABORT)
 * ------------------------------------------------------------------ */

#define SS_ABORT_TIMEOUT                  0x01
#define SS_ABORT_PROTOCOL_VIOLATION       0x02
#define SS_ABORT_OPERATOR_MANUAL          0x03
#define SS_ABORT_ON_CHAIN_CONFLICT        0x04
#define SS_ABORT_REVOCATION_INVALID       0x05
#define SS_ABORT_UNSPECIFIED              0xFF

/* ------------------------------------------------------------------
 * Confirmation status codes (carried inside CEREMONY_RESULT)
 * ------------------------------------------------------------------ */

#define SS_RESULT_AGGREGATED_ONLY         0x00  /* sig computed; not broadcast yet */
#define SS_RESULT_BROADCAST_MEMPOOL       0x01  /* broadcast; in mempool */
#define SS_RESULT_BROADCAST_CONFIRMED     0x02  /* broadcast; confirmed on-chain */

/* ------------------------------------------------------------------
 * Participant phase enum (used in STATUS_REPLY and persist tables).
 * Mirrors ceremony_participants.phase in libsuperscalar SQLite.
 * ------------------------------------------------------------------ */

#define SS_PHASE_NOT_SENT                 0x00
#define SS_PHASE_SENT                     0x01
#define SS_PHASE_NONCED                   0x02
#define SS_PHASE_SIGNED                   0x03
#define SS_PHASE_TIMED_OUT                0x04
#define SS_PHASE_REFUSED                  0x05

/* ------------------------------------------------------------------
 * Common byte sizes
 * ------------------------------------------------------------------ */

#define SS_CEREMONY_ID_LEN                8
#define SS_FACTORY_INSTANCE_ID_LEN        32
#define SS_MUSIG2_PUBNONCE_LEN            66  /* two 33-byte points R1 || R2 */
#define SS_MUSIG2_PARTIAL_SIG_LEN         32
#define SS_AGGREGATED_SCHNORR_SIG_LEN     64  /* BIP-340 form */
#define SS_REVOCATION_SECRET_LEN          32
#define SS_MESSAGE_HASH_LEN               32  /* sighash, 32 bytes */
#define SS_TXID_LEN                       32

/* ------------------------------------------------------------------
 * Per-submsg payload structs
 * ------------------------------------------------------------------ */

struct ss_ceremony_start_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  type;
	uint8_t  factory_instance_id[SS_FACTORY_INSTANCE_ID_LEN];
	uint8_t  parent_ceremony_id[SS_CEREMONY_ID_LEN];  /* all-zero = no parent */
	uint32_t deadline_block;
	uint64_t deadline_epoch_secs;
	uint8_t  lsp_nonce[SS_MUSIG2_PUBNONCE_LEN];
	const uint8_t *tx_templates;     /* pointer into wire buffer; valid only during decode */
	size_t   tx_templates_len;
};

struct ss_ceremony_nonce_reply_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  refuse_code;            /* SS_REFUSE_NONE = nonce reply; else refusal */
	uint8_t  participant_nonce[SS_MUSIG2_PUBNONCE_LEN]; /* valid only when refuse_code==NONE */
};

struct ss_ceremony_partial_sig_req_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  aggregated_nonce[SS_MUSIG2_PUBNONCE_LEN];
	uint16_t n_message_hashes;
	const uint8_t *message_hashes;   /* pointer into wire buffer; n_message_hashes * 32 bytes */
};

struct ss_ceremony_partial_sig_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint16_t n_partial_sigs;
	const uint8_t *partial_sigs;     /* pointer into wire buffer; n_partial_sigs * 32 bytes */
	uint16_t n_revocation_secrets;
	const uint8_t *revocation_secrets; /* pointer into wire buffer; n_revocation_secrets * 32 bytes */
};

struct ss_ceremony_result_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  final_signature[SS_AGGREGATED_SCHNORR_SIG_LEN];
	uint8_t  txid[SS_TXID_LEN];      /* all-zero = not broadcast */
	uint8_t  confirmation_status;
};

struct ss_ceremony_abort_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  reason_code;
};

struct ss_ceremony_status_query_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
};

struct ss_ceremony_status_reply_msg {
	uint8_t  ceremony_id[SS_CEREMONY_ID_LEN];
	uint8_t  current_phase;
	uint8_t  expected_next_submsg;   /* low byte of expected submsg ID; e.g. 0x46 = NONCE_REPLY */
};

/* ------------------------------------------------------------------
 * Encode functions
 *
 * Each returns the number of bytes written to `out` on success, or 0
 * on failure (output buffer too small or invalid input). Caller is
 * responsible for sizing `out` appropriately; see SS_*_MAX_LEN macros
 * below for safe sizing.
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_start(uint8_t *out, size_t out_len,
				 const struct ss_ceremony_start_msg *msg);

size_t ss_encode_ceremony_nonce_reply(uint8_t *out, size_t out_len,
				       const struct ss_ceremony_nonce_reply_msg *msg);

size_t ss_encode_ceremony_partial_sig_req(uint8_t *out, size_t out_len,
					   const struct ss_ceremony_partial_sig_req_msg *msg);

size_t ss_encode_ceremony_partial_sig(uint8_t *out, size_t out_len,
				       const struct ss_ceremony_partial_sig_msg *msg);

size_t ss_encode_ceremony_result(uint8_t *out, size_t out_len,
				  const struct ss_ceremony_result_msg *msg);

size_t ss_encode_ceremony_abort(uint8_t *out, size_t out_len,
				 const struct ss_ceremony_abort_msg *msg);

size_t ss_encode_ceremony_status_query(uint8_t *out, size_t out_len,
					const struct ss_ceremony_status_query_msg *msg);

size_t ss_encode_ceremony_status_reply(uint8_t *out, size_t out_len,
					const struct ss_ceremony_status_reply_msg *msg);

/* ------------------------------------------------------------------
 * Decode functions
 *
 * Each parses `in` (of length `in_len`) into the output struct.
 * Returns true on success, false on malformed input.
 *
 * For messages with pointer fields (CEREMONY_START.tx_templates,
 * PARTIAL_SIG_REQ.message_hashes, PARTIAL_SIG.partial_sigs +
 * revocation_secrets), the pointers reference into the caller-owned
 * `in` buffer and are only valid for its lifetime.
 * ------------------------------------------------------------------ */

bool ss_decode_ceremony_start(const uint8_t *in, size_t in_len,
			       struct ss_ceremony_start_msg *out);

bool ss_decode_ceremony_nonce_reply(const uint8_t *in, size_t in_len,
				     struct ss_ceremony_nonce_reply_msg *out);

bool ss_decode_ceremony_partial_sig_req(const uint8_t *in, size_t in_len,
					 struct ss_ceremony_partial_sig_req_msg *out);

bool ss_decode_ceremony_partial_sig(const uint8_t *in, size_t in_len,
				     struct ss_ceremony_partial_sig_msg *out);

bool ss_decode_ceremony_result(const uint8_t *in, size_t in_len,
				struct ss_ceremony_result_msg *out);

bool ss_decode_ceremony_abort(const uint8_t *in, size_t in_len,
			       struct ss_ceremony_abort_msg *out);

bool ss_decode_ceremony_status_query(const uint8_t *in, size_t in_len,
				      struct ss_ceremony_status_query_msg *out);

bool ss_decode_ceremony_status_reply(const uint8_t *in, size_t in_len,
				      struct ss_ceremony_status_reply_msg *out);

/* ------------------------------------------------------------------
 * Maximum encoded sizes — useful for caller buffer sizing.
 * SS_CEREMONY_START_MAX_LEN accounts for the largest reasonable
 * tx_templates payload (16 KB) for an INITIAL ceremony.
 * ------------------------------------------------------------------ */

#define SS_CEREMONY_START_FIXED_LEN       (8 + 1 + 32 + 8 + 4 + 8 + 66 + 2)  /* 129 */
#define SS_CEREMONY_TX_TEMPLATES_MAX_LEN  (16 * 1024)
#define SS_CEREMONY_START_MAX_LEN         (SS_CEREMONY_START_FIXED_LEN + SS_CEREMONY_TX_TEMPLATES_MAX_LEN)

#define SS_CEREMONY_NONCE_REPLY_MAX_LEN   (8 + 1 + 66)  /* 75 */
#define SS_CEREMONY_PARTIAL_SIG_REQ_FIXED_LEN  (8 + 66 + 2)  /* 76 */
#define SS_CEREMONY_PARTIAL_SIG_FIXED_LEN      (8 + 2 + 2)   /* 12 */
#define SS_CEREMONY_RESULT_LEN            (8 + 64 + 32 + 1)  /* 105 */
#define SS_CEREMONY_ABORT_LEN             (8 + 1)            /* 9 */
#define SS_CEREMONY_STATUS_QUERY_LEN      (8)
#define SS_CEREMONY_STATUS_REPLY_LEN      (8 + 1 + 1)        /* 10 */

#endif /* SUPERSCALAR_CEREMONY_WIRE_H */
