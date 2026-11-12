/* SuperScalar bLIP-56 factory_protocol_id.
 *
 * Value: SHA-256 of the UTF-8 bytes "SuperScalar/1" (protocol name and
 * major version, "/" separator), the form bLIP-56 recommends:
 *   SHA256(53757065725363616c61722f31) =
 *   c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1
 */
#ifndef SS_PROTOCOL_ID_H
#define SS_PROTOCOL_ID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SUPERSCALAR_PROTOCOL_ID_HEX \
	"c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1"

static const uint8_t SUPERSCALAR_PROTOCOL_ID[32] = {
	0xc3, 0xa0, 0x82, 0xd0, 0xfc, 0xb7, 0x68, 0xd7,
	0x69, 0x99, 0xf4, 0xf8, 0xad, 0x67, 0x2f, 0x71,
	0x10, 0xfb, 0xef, 0x6a, 0x13, 0xa1, 0x69, 0x76,
	0x86, 0xc7, 0x07, 0x39, 0x61, 0xc8, 0x42, 0xf1
};

/* A factory_piggyback body starts with TLV 0 (type 0x00, len 0x20,
 * 32-byte protocol id). True only if that TLV carries our protocol id. */
static inline bool ss_piggyback_is_superscalar(const uint8_t *data, size_t len)
{
	if (!data || len < 34 || data[0] != 0x00 || data[1] != 32)
		return false;
	return memcmp(data + 2, SUPERSCALAR_PROTOCOL_ID, 32) == 0;
}

#endif /* SS_PROTOCOL_ID_H */
