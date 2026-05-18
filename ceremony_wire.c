/* Wire codec for trigger-ceremony submsgs 0x0145-0x014C.
 * See ceremony_wire.h for format documentation.
 *
 * Endianness: all multi-byte integers are big-endian (network order),
 * matching the existing 0x0140-0x0144 codec style.
 *
 * No memory allocation: encoders write into caller-provided buffer;
 * decoders return pointers into caller-owned input buffer for
 * variable-length fields.
 */

#include "ceremony_wire.h"
#include <string.h>

/* ------------------------------------------------------------------
 * Internal byte-pushing helpers
 * ------------------------------------------------------------------ */

static inline void put_u16_be(uint8_t **p, uint16_t v) {
	(*p)[0] = (v >> 8) & 0xFF;
	(*p)[1] = v & 0xFF;
	*p += 2;
}

static inline void put_u32_be(uint8_t **p, uint32_t v) {
	for (int k = 3; k >= 0; k--) {
		**p = (v >> (k * 8)) & 0xFF;
		(*p)++;
	}
}

static inline void put_u64_be(uint8_t **p, uint64_t v) {
	for (int k = 7; k >= 0; k--) {
		**p = (v >> (k * 8)) & 0xFF;
		(*p)++;
	}
}

static inline uint16_t get_u16_be(const uint8_t **p) {
	uint16_t v = ((uint16_t)(*p)[0] << 8) | (*p)[1];
	*p += 2;
	return v;
}

static inline uint32_t get_u32_be(const uint8_t **p) {
	uint32_t v = 0;
	for (int k = 0; k < 4; k++) v = (v << 8) | (*p)[k];
	*p += 4;
	return v;
}

static inline uint64_t get_u64_be(const uint8_t **p) {
	uint64_t v = 0;
	for (int k = 0; k < 8; k++) v = (v << 8) | (*p)[k];
	*p += 8;
	return v;
}

/* ------------------------------------------------------------------
 * 0x0145 CEREMONY_START
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_start(uint8_t *out, size_t out_len,
				 const struct ss_ceremony_start_msg *msg)
{
	if (!out || !msg) return 0;
	if (msg->tx_templates_len > SS_CEREMONY_TX_TEMPLATES_MAX_LEN) return 0;
	size_t need = SS_CEREMONY_START_FIXED_LEN + msg->tx_templates_len;
	if (out_len < need) return 0;
	if (msg->tx_templates_len > 0 && !msg->tx_templates) return 0;

	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	*p++ = msg->type;
	memcpy(p, msg->factory_instance_id, SS_FACTORY_INSTANCE_ID_LEN);
	p += SS_FACTORY_INSTANCE_ID_LEN;
	memcpy(p, msg->parent_ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	put_u32_be(&p, msg->deadline_block);
	put_u64_be(&p, msg->deadline_epoch_secs);
	memcpy(p, msg->lsp_nonce, SS_MUSIG2_PUBNONCE_LEN); p += SS_MUSIG2_PUBNONCE_LEN;
	put_u16_be(&p, (uint16_t)msg->tx_templates_len);
	if (msg->tx_templates_len > 0) {
		memcpy(p, msg->tx_templates, msg->tx_templates_len);
		p += msg->tx_templates_len;
	}
	return (size_t)(p - out);
}

bool ss_decode_ceremony_start(const uint8_t *in, size_t in_len,
			       struct ss_ceremony_start_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_START_FIXED_LEN) return false;

	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->type = *p++;
	memcpy(out->factory_instance_id, p, SS_FACTORY_INSTANCE_ID_LEN);
	p += SS_FACTORY_INSTANCE_ID_LEN;
	memcpy(out->parent_ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->deadline_block = get_u32_be(&p);
	out->deadline_epoch_secs = get_u64_be(&p);
	memcpy(out->lsp_nonce, p, SS_MUSIG2_PUBNONCE_LEN); p += SS_MUSIG2_PUBNONCE_LEN;
	uint16_t tx_len = get_u16_be(&p);

	if ((size_t)(p - in) + tx_len > in_len) return false;
	if (tx_len > SS_CEREMONY_TX_TEMPLATES_MAX_LEN) return false;

	out->tx_templates_len = tx_len;
	out->tx_templates = (tx_len > 0) ? p : NULL;
	return true;
}

/* ------------------------------------------------------------------
 * 0x0146 CEREMONY_NONCE_REPLY
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_nonce_reply(uint8_t *out, size_t out_len,
				       const struct ss_ceremony_nonce_reply_msg *msg)
{
	if (!out || !msg) return 0;
	bool with_nonce = (msg->refuse_code == SS_REFUSE_NONE);
	size_t need = with_nonce
		? (SS_CEREMONY_ID_LEN + 1 + SS_MUSIG2_PUBNONCE_LEN)
		: (SS_CEREMONY_ID_LEN + 1);
	if (out_len < need) return 0;

	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	*p++ = msg->refuse_code;
	if (with_nonce) {
		memcpy(p, msg->participant_nonce, SS_MUSIG2_PUBNONCE_LEN);
		p += SS_MUSIG2_PUBNONCE_LEN;
	}
	return (size_t)(p - out);
}

bool ss_decode_ceremony_nonce_reply(const uint8_t *in, size_t in_len,
				     struct ss_ceremony_nonce_reply_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_ID_LEN + 1) return false;

	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->refuse_code = *p++;

	if (out->refuse_code == SS_REFUSE_NONE) {
		if (in_len < SS_CEREMONY_ID_LEN + 1 + SS_MUSIG2_PUBNONCE_LEN) return false;
		memcpy(out->participant_nonce, p, SS_MUSIG2_PUBNONCE_LEN);
	} else {
		memset(out->participant_nonce, 0, SS_MUSIG2_PUBNONCE_LEN);
	}
	return true;
}

/* ------------------------------------------------------------------
 * 0x0147 CEREMONY_PARTIAL_SIG_REQ
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_partial_sig_req(uint8_t *out, size_t out_len,
					   const struct ss_ceremony_partial_sig_req_msg *msg)
{
	if (!out || !msg) return 0;
	if (msg->n_message_hashes > 0 && !msg->message_hashes) return 0;
	size_t need = SS_CEREMONY_PARTIAL_SIG_REQ_FIXED_LEN
	            + (size_t)msg->n_message_hashes * SS_MESSAGE_HASH_LEN;
	if (out_len < need) return 0;

	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	memcpy(p, msg->aggregated_nonce, SS_MUSIG2_PUBNONCE_LEN);
	p += SS_MUSIG2_PUBNONCE_LEN;
	put_u16_be(&p, msg->n_message_hashes);
	if (msg->n_message_hashes > 0) {
		memcpy(p, msg->message_hashes,
		       (size_t)msg->n_message_hashes * SS_MESSAGE_HASH_LEN);
		p += (size_t)msg->n_message_hashes * SS_MESSAGE_HASH_LEN;
	}
	return (size_t)(p - out);
}

bool ss_decode_ceremony_partial_sig_req(const uint8_t *in, size_t in_len,
					 struct ss_ceremony_partial_sig_req_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_PARTIAL_SIG_REQ_FIXED_LEN) return false;

	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	memcpy(out->aggregated_nonce, p, SS_MUSIG2_PUBNONCE_LEN);
	p += SS_MUSIG2_PUBNONCE_LEN;
	out->n_message_hashes = get_u16_be(&p);

	size_t hashes_len = (size_t)out->n_message_hashes * SS_MESSAGE_HASH_LEN;
	if ((size_t)(p - in) + hashes_len > in_len) return false;

	out->message_hashes = (out->n_message_hashes > 0) ? p : NULL;
	return true;
}

/* ------------------------------------------------------------------
 * 0x0148 CEREMONY_PARTIAL_SIG
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_partial_sig(uint8_t *out, size_t out_len,
				       const struct ss_ceremony_partial_sig_msg *msg)
{
	if (!out || !msg) return 0;
	if (msg->n_partial_sigs > 0 && !msg->partial_sigs) return 0;
	if (msg->n_revocation_secrets > 0 && !msg->revocation_secrets) return 0;

	size_t sigs_len = (size_t)msg->n_partial_sigs * SS_MUSIG2_PARTIAL_SIG_LEN;
	size_t revs_len = (size_t)msg->n_revocation_secrets * SS_REVOCATION_SECRET_LEN;
	size_t need = SS_CEREMONY_ID_LEN + 2 + sigs_len + 2 + revs_len;
	if (out_len < need) return 0;

	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	put_u16_be(&p, msg->n_partial_sigs);
	if (sigs_len > 0) {
		memcpy(p, msg->partial_sigs, sigs_len);
		p += sigs_len;
	}
	put_u16_be(&p, msg->n_revocation_secrets);
	if (revs_len > 0) {
		memcpy(p, msg->revocation_secrets, revs_len);
		p += revs_len;
	}
	return (size_t)(p - out);
}

bool ss_decode_ceremony_partial_sig(const uint8_t *in, size_t in_len,
				     struct ss_ceremony_partial_sig_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_ID_LEN + 2) return false;

	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->n_partial_sigs = get_u16_be(&p);
	size_t sigs_len = (size_t)out->n_partial_sigs * SS_MUSIG2_PARTIAL_SIG_LEN;
	if ((size_t)(p - in) + sigs_len + 2 > in_len) return false;
	out->partial_sigs = (out->n_partial_sigs > 0) ? p : NULL;
	p += sigs_len;
	out->n_revocation_secrets = get_u16_be(&p);
	size_t revs_len = (size_t)out->n_revocation_secrets * SS_REVOCATION_SECRET_LEN;
	if ((size_t)(p - in) + revs_len > in_len) return false;
	out->revocation_secrets = (out->n_revocation_secrets > 0) ? p : NULL;
	return true;
}

/* ------------------------------------------------------------------
 * 0x0149 CEREMONY_RESULT
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_result(uint8_t *out, size_t out_len,
				  const struct ss_ceremony_result_msg *msg)
{
	if (!out || !msg) return 0;
	if (out_len < SS_CEREMONY_RESULT_LEN) return 0;

	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	memcpy(p, msg->final_signature, SS_AGGREGATED_SCHNORR_SIG_LEN);
	p += SS_AGGREGATED_SCHNORR_SIG_LEN;
	memcpy(p, msg->txid, SS_TXID_LEN); p += SS_TXID_LEN;
	*p++ = msg->confirmation_status;
	return (size_t)(p - out);
}

bool ss_decode_ceremony_result(const uint8_t *in, size_t in_len,
				struct ss_ceremony_result_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_RESULT_LEN) return false;

	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	memcpy(out->final_signature, p, SS_AGGREGATED_SCHNORR_SIG_LEN);
	p += SS_AGGREGATED_SCHNORR_SIG_LEN;
	memcpy(out->txid, p, SS_TXID_LEN); p += SS_TXID_LEN;
	out->confirmation_status = *p++;
	return true;
}

/* ------------------------------------------------------------------
 * 0x014A CEREMONY_ABORT
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_abort(uint8_t *out, size_t out_len,
				 const struct ss_ceremony_abort_msg *msg)
{
	if (!out || !msg) return 0;
	if (out_len < SS_CEREMONY_ABORT_LEN) return 0;
	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	*p++ = msg->reason_code;
	return (size_t)(p - out);
}

bool ss_decode_ceremony_abort(const uint8_t *in, size_t in_len,
			       struct ss_ceremony_abort_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_ABORT_LEN) return false;
	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->reason_code = *p++;
	return true;
}

/* ------------------------------------------------------------------
 * 0x014B CEREMONY_STATUS_QUERY
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_status_query(uint8_t *out, size_t out_len,
					const struct ss_ceremony_status_query_msg *msg)
{
	if (!out || !msg) return 0;
	if (out_len < SS_CEREMONY_STATUS_QUERY_LEN) return 0;
	memcpy(out, msg->ceremony_id, SS_CEREMONY_ID_LEN);
	return SS_CEREMONY_STATUS_QUERY_LEN;
}

bool ss_decode_ceremony_status_query(const uint8_t *in, size_t in_len,
				      struct ss_ceremony_status_query_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_STATUS_QUERY_LEN) return false;
	memcpy(out->ceremony_id, in, SS_CEREMONY_ID_LEN);
	return true;
}

/* ------------------------------------------------------------------
 * 0x014C CEREMONY_STATUS_REPLY
 * ------------------------------------------------------------------ */

size_t ss_encode_ceremony_status_reply(uint8_t *out, size_t out_len,
					const struct ss_ceremony_status_reply_msg *msg)
{
	if (!out || !msg) return 0;
	if (out_len < SS_CEREMONY_STATUS_REPLY_LEN) return 0;
	uint8_t *p = out;
	memcpy(p, msg->ceremony_id, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	*p++ = msg->current_phase;
	*p++ = msg->expected_next_submsg;
	return (size_t)(p - out);
}

bool ss_decode_ceremony_status_reply(const uint8_t *in, size_t in_len,
				      struct ss_ceremony_status_reply_msg *out)
{
	if (!in || !out) return false;
	if (in_len < SS_CEREMONY_STATUS_REPLY_LEN) return false;
	const uint8_t *p = in;
	memcpy(out->ceremony_id, p, SS_CEREMONY_ID_LEN); p += SS_CEREMONY_ID_LEN;
	out->current_phase = *p++;
	out->expected_next_submsg = *p++;
	return true;
}
