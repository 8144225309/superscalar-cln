/* Nonce exchange serialization */
#include <string.h>
#include "nonce_exchange.h"

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (v >> 24) & 0xFF;
	p[1] = (v >> 16) & 0xFF;
	p[2] = (v >> 8) & 0xFF;
	p[3] = v & 0xFF;
}

static uint32_t get_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

size_t nonce_bundle_serialize(const nonce_bundle_t *nb,
			      uint8_t *out, size_t out_max)
{
	/* Header: instance_id(32) + n_participants(4) + n_nodes(4) + n_entries(4)
	 *        + pubkeys(n_participants * 33) */
	/* Per entry: node_idx(4) + signer_slot(4) + pubnonce(66) = 74 */
	size_t funding_trailer = 1 + (nb->funding_spk_len > 0
		? 32 + 4 + 8 + nb->funding_spk_len : 0);
	size_t needed = 44 + nb->n_participants * 33
		+ nb->n_entries * 74 + funding_trailer;
	if (out_max < needed)
		return 0;

	uint8_t *p = out;
	memcpy(p, nb->instance_id, 32); p += 32;
	put_u32(p, nb->n_participants); p += 4;
	put_u32(p, nb->n_nodes); p += 4;
	put_u32(p, nb->n_entries); p += 4;

	/* Pubkeys for all participants */
	for (uint32_t i = 0; i < nb->n_participants; i++) {
		memcpy(p, nb->pubkeys[i], 33);
		p += 33;
	}

	for (size_t i = 0; i < nb->n_entries; i++) {
		put_u32(p, nb->entries[i].node_idx); p += 4;
		put_u32(p, nb->entries[i].signer_slot); p += 4;
		memcpy(p, nb->entries[i].pubnonce, 66); p += 66;
	}

	/* Funding info trailer (backward-compatible: old readers stop here).
	 * funding_spk_len=0 means no funding data present. */
	*p++ = nb->funding_spk_len;
	if (nb->funding_spk_len > 0) {
		memcpy(p, nb->funding_txid, 32); p += 32;
		put_u32(p, nb->funding_vout); p += 4;
		/* 8-byte amount, big-endian */
		uint64_t amt = nb->funding_amount_sats;
		p[0] = (amt >> 56) & 0xFF; p[1] = (amt >> 48) & 0xFF;
		p[2] = (amt >> 40) & 0xFF; p[3] = (amt >> 32) & 0xFF;
		p[4] = (amt >> 24) & 0xFF; p[5] = (amt >> 16) & 0xFF;
		p[6] = (amt >>  8) & 0xFF; p[7] = amt & 0xFF;
		p += 8;
		memcpy(p, nb->funding_spk, nb->funding_spk_len);
		p += nb->funding_spk_len;
	}

	return (size_t)(p - out);
}

int nonce_bundle_deserialize(nonce_bundle_t *nb,
			     const uint8_t *data, size_t len)
{
	if (len < 44) return 0;

	const uint8_t *p = data;
	memcpy(nb->instance_id, p, 32); p += 32;
	nb->n_participants = get_u32(p); p += 4;
	nb->n_nodes = get_u32(p); p += 4;
	nb->n_entries = get_u32(p); p += 4;

	if (nb->n_participants > MAX_PARTICIPANTS) return 0;
	if (nb->n_entries > MAX_NONCE_ENTRIES) return 0;

	/* Read pubkeys */
	size_t pk_bytes = nb->n_participants * 33;
	if (len < 44 + pk_bytes + nb->n_entries * 74) return 0;
	for (uint32_t i = 0; i < nb->n_participants; i++) {
		memcpy(nb->pubkeys[i], p, 33);
		p += 33;
	}

	for (size_t i = 0; i < nb->n_entries; i++) {
		nb->entries[i].node_idx = get_u32(p); p += 4;
		nb->entries[i].signer_slot = get_u32(p); p += 4;
		memcpy(nb->entries[i].pubnonce, p, 66); p += 66;
	}

	/* Read optional funding info trailer (backward-compatible) */
	size_t consumed = (size_t)(p - data);
	nb->funding_spk_len = 0;
	if (consumed < len) {
		nb->funding_spk_len = *p++;
		if (nb->funding_spk_len > 0 &&
		    nb->funding_spk_len <= 34 &&
		    consumed + 1 + 32 + 4 + 8 + nb->funding_spk_len <= len) {
			memcpy(nb->funding_txid, p, 32); p += 32;
			nb->funding_vout = get_u32(p); p += 4;
			nb->funding_amount_sats =
				((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
				((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
				((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
				((uint64_t)p[6] <<  8) | p[7];
			p += 8;
			memcpy(nb->funding_spk, p, nb->funding_spk_len);
		} else {
			nb->funding_spk_len = 0;
		}
	}

	return 1;
}
