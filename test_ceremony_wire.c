/* Round-trip unit tests for ceremony_wire codec.
 *
 * Build: cc -I. -o test_ceremony_wire ceremony_wire.c test_ceremony_wire.c
 * Run:   ./test_ceremony_wire
 *
 * Exit 0 on all-pass; non-zero on first failure with diagnostic line.
 */

#include "ceremony_wire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

static int fails = 0;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define CHECK_BYTES_EQ(a, b, n) do { \
	if (memcmp((a), (b), (n)) != 0) { \
		fprintf(stderr, "FAIL %s:%d  bytes diff over %zu\n", \
		        __FILE__, __LINE__, (size_t)(n)); \
		fails++; \
	} \
} while (0)

static void fill_pattern(uint8_t *buf, size_t n, uint8_t seed)
{
	for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(seed + i);
}

/* ------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------ */

static void test_ceremony_start_roundtrip(void)
{
	struct ss_ceremony_start_msg in_msg;
	uint8_t tx_templates[200];
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0x10);
	in_msg.type = SS_CEREMONY_TYPE_ROTATE;
	fill_pattern(in_msg.factory_instance_id, SS_FACTORY_INSTANCE_ID_LEN, 0x20);
	fill_pattern(in_msg.parent_ceremony_id, SS_CEREMONY_ID_LEN, 0x30);
	in_msg.deadline_block = 0x12345678;
	in_msg.deadline_epoch_secs = 0xCAFEBABEDEADBEEFULL;
	fill_pattern(in_msg.lsp_nonce, SS_MUSIG2_PUBNONCE_LEN, 0x40);
	fill_pattern(tx_templates, sizeof tx_templates, 0x50);
	in_msg.tx_templates = tx_templates;
	in_msg.tx_templates_len = sizeof tx_templates;

	uint8_t buf[SS_CEREMONY_START_FIXED_LEN + 200];
	size_t n = ss_encode_ceremony_start(buf, sizeof buf, &in_msg);
	CHECK(n == SS_CEREMONY_START_FIXED_LEN + 200);

	struct ss_ceremony_start_msg out_msg;
	memset(&out_msg, 0, sizeof out_msg);
	CHECK(ss_decode_ceremony_start(buf, n, &out_msg));
	CHECK_BYTES_EQ(in_msg.ceremony_id, out_msg.ceremony_id, SS_CEREMONY_ID_LEN);
	CHECK(in_msg.type == out_msg.type);
	CHECK_BYTES_EQ(in_msg.factory_instance_id, out_msg.factory_instance_id,
		       SS_FACTORY_INSTANCE_ID_LEN);
	CHECK_BYTES_EQ(in_msg.parent_ceremony_id, out_msg.parent_ceremony_id,
		       SS_CEREMONY_ID_LEN);
	CHECK(in_msg.deadline_block == out_msg.deadline_block);
	CHECK(in_msg.deadline_epoch_secs == out_msg.deadline_epoch_secs);
	CHECK_BYTES_EQ(in_msg.lsp_nonce, out_msg.lsp_nonce, SS_MUSIG2_PUBNONCE_LEN);
	CHECK(in_msg.tx_templates_len == out_msg.tx_templates_len);
	CHECK_BYTES_EQ(tx_templates, out_msg.tx_templates, sizeof tx_templates);
}

static void test_ceremony_start_zero_tx_templates(void)
{
	struct ss_ceremony_start_msg in_msg;
	memset(&in_msg, 0, sizeof in_msg);
	in_msg.type = SS_CEREMONY_TYPE_INITIAL;
	in_msg.deadline_block = 100;
	in_msg.tx_templates = NULL;
	in_msg.tx_templates_len = 0;

	uint8_t buf[SS_CEREMONY_START_FIXED_LEN];
	size_t n = ss_encode_ceremony_start(buf, sizeof buf, &in_msg);
	CHECK(n == SS_CEREMONY_START_FIXED_LEN);

	struct ss_ceremony_start_msg out_msg;
	CHECK(ss_decode_ceremony_start(buf, n, &out_msg));
	CHECK(out_msg.tx_templates_len == 0);
	CHECK(out_msg.tx_templates == NULL);
}

static void test_ceremony_start_buffer_too_small(void)
{
	struct ss_ceremony_start_msg in_msg;
	memset(&in_msg, 0, sizeof in_msg);
	uint8_t tiny[10];
	CHECK(ss_encode_ceremony_start(tiny, sizeof tiny, &in_msg) == 0);
}

static void test_ceremony_nonce_reply_with_nonce(void)
{
	struct ss_ceremony_nonce_reply_msg in_msg;
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0xA0);
	in_msg.refuse_code = SS_REFUSE_NONE;
	fill_pattern(in_msg.participant_nonce, SS_MUSIG2_PUBNONCE_LEN, 0xB0);

	uint8_t buf[SS_CEREMONY_NONCE_REPLY_MAX_LEN];
	size_t n = ss_encode_ceremony_nonce_reply(buf, sizeof buf, &in_msg);
	CHECK(n == 8 + 1 + SS_MUSIG2_PUBNONCE_LEN);

	struct ss_ceremony_nonce_reply_msg out_msg;
	CHECK(ss_decode_ceremony_nonce_reply(buf, n, &out_msg));
	CHECK_BYTES_EQ(in_msg.ceremony_id, out_msg.ceremony_id, SS_CEREMONY_ID_LEN);
	CHECK(out_msg.refuse_code == SS_REFUSE_NONE);
	CHECK_BYTES_EQ(in_msg.participant_nonce, out_msg.participant_nonce,
		       SS_MUSIG2_PUBNONCE_LEN);
}

static void test_ceremony_nonce_reply_refuse(void)
{
	struct ss_ceremony_nonce_reply_msg in_msg;
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0xA1);
	in_msg.refuse_code = SS_REFUSE_SEQUENCING_VIOLATION;
	/* participant_nonce content should be ignored in encode */

	uint8_t buf[SS_CEREMONY_NONCE_REPLY_MAX_LEN];
	size_t n = ss_encode_ceremony_nonce_reply(buf, sizeof buf, &in_msg);
	CHECK(n == 9);  /* no nonce when refusing */

	struct ss_ceremony_nonce_reply_msg out_msg;
	CHECK(ss_decode_ceremony_nonce_reply(buf, n, &out_msg));
	CHECK(out_msg.refuse_code == SS_REFUSE_SEQUENCING_VIOLATION);
}

static void test_partial_sig_req_roundtrip(void)
{
	struct ss_ceremony_partial_sig_req_msg in_msg;
	uint8_t hashes[3 * SS_MESSAGE_HASH_LEN];
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0xC0);
	fill_pattern(in_msg.aggregated_nonce, SS_MUSIG2_PUBNONCE_LEN, 0xC1);
	in_msg.n_message_hashes = 3;
	fill_pattern(hashes, sizeof hashes, 0xC2);
	in_msg.message_hashes = hashes;

	uint8_t buf[SS_CEREMONY_PARTIAL_SIG_REQ_FIXED_LEN + sizeof hashes];
	size_t n = ss_encode_ceremony_partial_sig_req(buf, sizeof buf, &in_msg);
	CHECK(n == sizeof buf);

	struct ss_ceremony_partial_sig_req_msg out_msg;
	CHECK(ss_decode_ceremony_partial_sig_req(buf, n, &out_msg));
	CHECK(out_msg.n_message_hashes == 3);
	CHECK_BYTES_EQ(hashes, out_msg.message_hashes, sizeof hashes);
}

static void test_partial_sig_roundtrip(void)
{
	struct ss_ceremony_partial_sig_msg in_msg;
	uint8_t sigs[2 * SS_MUSIG2_PARTIAL_SIG_LEN];
	uint8_t revs[1 * SS_REVOCATION_SECRET_LEN];
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0xD0);
	in_msg.n_partial_sigs = 2;
	fill_pattern(sigs, sizeof sigs, 0xD1);
	in_msg.partial_sigs = sigs;
	in_msg.n_revocation_secrets = 1;
	fill_pattern(revs, sizeof revs, 0xD2);
	in_msg.revocation_secrets = revs;

	uint8_t buf[SS_CEREMONY_PARTIAL_SIG_FIXED_LEN + sizeof sigs + sizeof revs];
	size_t n = ss_encode_ceremony_partial_sig(buf, sizeof buf, &in_msg);
	CHECK(n == sizeof buf);

	struct ss_ceremony_partial_sig_msg out_msg;
	CHECK(ss_decode_ceremony_partial_sig(buf, n, &out_msg));
	CHECK(out_msg.n_partial_sigs == 2);
	CHECK_BYTES_EQ(sigs, out_msg.partial_sigs, sizeof sigs);
	CHECK(out_msg.n_revocation_secrets == 1);
	CHECK_BYTES_EQ(revs, out_msg.revocation_secrets, sizeof revs);
}

static void test_partial_sig_zero_revocations(void)
{
	struct ss_ceremony_partial_sig_msg in_msg;
	uint8_t sigs[SS_MUSIG2_PARTIAL_SIG_LEN];
	memset(&in_msg, 0, sizeof in_msg);
	in_msg.n_partial_sigs = 1;
	in_msg.partial_sigs = sigs;
	in_msg.n_revocation_secrets = 0;
	in_msg.revocation_secrets = NULL;
	fill_pattern(sigs, sizeof sigs, 0xE0);

	uint8_t buf[64];
	size_t n = ss_encode_ceremony_partial_sig(buf, sizeof buf, &in_msg);
	CHECK(n == 8 + 2 + sizeof sigs + 2);

	struct ss_ceremony_partial_sig_msg out_msg;
	CHECK(ss_decode_ceremony_partial_sig(buf, n, &out_msg));
	CHECK(out_msg.n_partial_sigs == 1);
	CHECK(out_msg.n_revocation_secrets == 0);
	CHECK(out_msg.revocation_secrets == NULL);
}

static void test_ceremony_result_roundtrip(void)
{
	struct ss_ceremony_result_msg in_msg;
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0x70);
	fill_pattern(in_msg.final_signature, SS_AGGREGATED_SCHNORR_SIG_LEN, 0x71);
	fill_pattern(in_msg.txid, SS_TXID_LEN, 0x72);
	in_msg.confirmation_status = SS_RESULT_BROADCAST_MEMPOOL;

	uint8_t buf[SS_CEREMONY_RESULT_LEN];
	size_t n = ss_encode_ceremony_result(buf, sizeof buf, &in_msg);
	CHECK(n == SS_CEREMONY_RESULT_LEN);

	struct ss_ceremony_result_msg out_msg;
	CHECK(ss_decode_ceremony_result(buf, n, &out_msg));
	CHECK_BYTES_EQ(in_msg.final_signature, out_msg.final_signature,
		       SS_AGGREGATED_SCHNORR_SIG_LEN);
	CHECK_BYTES_EQ(in_msg.txid, out_msg.txid, SS_TXID_LEN);
	CHECK(out_msg.confirmation_status == SS_RESULT_BROADCAST_MEMPOOL);
}

static void test_ceremony_abort_roundtrip(void)
{
	struct ss_ceremony_abort_msg in_msg;
	fill_pattern(in_msg.ceremony_id, SS_CEREMONY_ID_LEN, 0x80);
	in_msg.reason_code = SS_ABORT_OPERATOR_MANUAL;

	uint8_t buf[SS_CEREMONY_ABORT_LEN];
	size_t n = ss_encode_ceremony_abort(buf, sizeof buf, &in_msg);
	CHECK(n == SS_CEREMONY_ABORT_LEN);

	struct ss_ceremony_abort_msg out_msg;
	CHECK(ss_decode_ceremony_abort(buf, n, &out_msg));
	CHECK_BYTES_EQ(in_msg.ceremony_id, out_msg.ceremony_id, SS_CEREMONY_ID_LEN);
	CHECK(out_msg.reason_code == SS_ABORT_OPERATOR_MANUAL);
}

static void test_status_query_reply_roundtrip(void)
{
	struct ss_ceremony_status_query_msg q;
	fill_pattern(q.ceremony_id, SS_CEREMONY_ID_LEN, 0x90);
	uint8_t qbuf[SS_CEREMONY_STATUS_QUERY_LEN];
	size_t qn = ss_encode_ceremony_status_query(qbuf, sizeof qbuf, &q);
	CHECK(qn == SS_CEREMONY_STATUS_QUERY_LEN);
	struct ss_ceremony_status_query_msg q_out;
	CHECK(ss_decode_ceremony_status_query(qbuf, qn, &q_out));
	CHECK_BYTES_EQ(q.ceremony_id, q_out.ceremony_id, SS_CEREMONY_ID_LEN);

	struct ss_ceremony_status_reply_msg r;
	memcpy(r.ceremony_id, q.ceremony_id, SS_CEREMONY_ID_LEN);
	r.current_phase = SS_PHASE_NONCED;
	r.expected_next_submsg = 0x47;  /* PARTIAL_SIG_REQ low byte */
	uint8_t rbuf[SS_CEREMONY_STATUS_REPLY_LEN];
	size_t rn = ss_encode_ceremony_status_reply(rbuf, sizeof rbuf, &r);
	CHECK(rn == SS_CEREMONY_STATUS_REPLY_LEN);
	struct ss_ceremony_status_reply_msg r_out;
	CHECK(ss_decode_ceremony_status_reply(rbuf, rn, &r_out));
	CHECK(r_out.current_phase == SS_PHASE_NONCED);
	CHECK(r_out.expected_next_submsg == 0x47);
}

static void test_decode_truncated_inputs(void)
{
	uint8_t tiny[3] = {0};
	struct ss_ceremony_start_msg s;
	CHECK(!ss_decode_ceremony_start(tiny, sizeof tiny, &s));

	struct ss_ceremony_nonce_reply_msg n;
	CHECK(!ss_decode_ceremony_nonce_reply(tiny, sizeof tiny, &n));

	struct ss_ceremony_partial_sig_req_msg q;
	CHECK(!ss_decode_ceremony_partial_sig_req(tiny, sizeof tiny, &q));

	struct ss_ceremony_partial_sig_msg p;
	CHECK(!ss_decode_ceremony_partial_sig(tiny, sizeof tiny, &p));

	struct ss_ceremony_result_msg r;
	CHECK(!ss_decode_ceremony_result(tiny, sizeof tiny, &r));

	struct ss_ceremony_abort_msg a;
	CHECK(!ss_decode_ceremony_abort(tiny, sizeof tiny, &a));

	struct ss_ceremony_status_query_msg sq;
	CHECK(!ss_decode_ceremony_status_query(tiny, sizeof tiny, &sq));

	struct ss_ceremony_status_reply_msg sr;
	CHECK(!ss_decode_ceremony_status_reply(tiny, sizeof tiny, &sr));
}

static void test_decode_invalid_tx_template_length(void)
{
	/* Build a CEREMONY_START header claiming a tx_templates length that
	 * extends past the buffer. Decoder must reject. */
	uint8_t buf[SS_CEREMONY_START_FIXED_LEN + 4];
	memset(buf, 0, sizeof buf);
	/* Set tx_templates_len at offset 127 to 0xFFFF; buffer only has 4 bytes after. */
	buf[127] = 0xFF;
	buf[128] = 0xFF;

	struct ss_ceremony_start_msg out;
	CHECK(!ss_decode_ceremony_start(buf, sizeof buf, &out));
}

int main(void)
{
	test_ceremony_start_roundtrip();
	test_ceremony_start_zero_tx_templates();
	test_ceremony_start_buffer_too_small();
	test_ceremony_nonce_reply_with_nonce();
	test_ceremony_nonce_reply_refuse();
	test_partial_sig_req_roundtrip();
	test_partial_sig_roundtrip();
	test_partial_sig_zero_revocations();
	test_ceremony_result_roundtrip();
	test_ceremony_abort_roundtrip();
	test_status_query_reply_roundtrip();
	test_decode_truncated_inputs();
	test_decode_invalid_tx_template_length();

	if (fails == 0) {
		printf("All ceremony_wire tests pass.\n");
		return 0;
	}
	fprintf(stderr, "%d ceremony_wire test failures.\n", fails);
	return 1;
}
