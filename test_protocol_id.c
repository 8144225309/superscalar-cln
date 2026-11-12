/* Unit tests for the factory_protocol_id constant and piggyback check.
 *
 * Build: cc -I. -o test_protocol_id test_protocol_id.c
 * Run:   ./test_protocol_id
 *
 * Exit 0 on all-pass; non-zero with diagnostics on failure.
 */
#include "protocol_id.h"
#include <stdio.h>

static int fails = 0;
static int checks = 0;

#define CHECK(cond) do { \
	checks++; \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/* TLV 0 protocol id + TLV 1024 header + 2-byte payload. */
static void make_envelope(uint8_t buf[40], const uint8_t id[32])
{
	buf[0] = 0x00; buf[1] = 32;
	memcpy(buf + 2, id, 32);
	buf[34] = 0xfd; buf[35] = 0x04; buf[36] = 0x00; buf[37] = 2;
	buf[38] = 0x00; buf[39] = 0x01;
}

int main(void)
{
	uint8_t env[40];
	char hex[65];

	for (int i = 0; i < 32; i++)
		sprintf(hex + i * 2, "%02x", SUPERSCALAR_PROTOCOL_ID[i]);
	CHECK(strcmp(hex, SUPERSCALAR_PROTOCOL_ID_HEX) == 0);

	/* Envelope carrying the SHA-256("SuperScalar/1") id is accepted. */
	make_envelope(env, SUPERSCALAR_PROTOCOL_ID);
	CHECK(ss_piggyback_is_superscalar(env, sizeof(env)));

	/* Envelope carrying the old zero-padded ASCII "SuperScalar/v1" id
	 * is ignored. */
	uint8_t old_id[32] = {0};
	memcpy(old_id, "SuperScalar/v1", 14);
	make_envelope(env, old_id);
	CHECK(!ss_piggyback_is_superscalar(env, sizeof(env)));

	/* Malformed TLV 0 header or truncated input is rejected. */
	make_envelope(env, SUPERSCALAR_PROTOCOL_ID);
	env[1] = 31;
	CHECK(!ss_piggyback_is_superscalar(env, sizeof(env)));
	make_envelope(env, SUPERSCALAR_PROTOCOL_ID);
	env[0] = 0x01;
	CHECK(!ss_piggyback_is_superscalar(env, sizeof(env)));
	make_envelope(env, SUPERSCALAR_PROTOCOL_ID);
	CHECK(!ss_piggyback_is_superscalar(env, 33));
	CHECK(!ss_piggyback_is_superscalar(NULL, sizeof(env)));

	if (fails) {
		fprintf(stderr, "%d/%d checks failed\n", fails, checks);
		return 1;
	}
	printf("test_protocol_id: %d/%d checks passed\n", checks, checks);
	return 0;
}
