/* Persistence layer — binary serialization for CLN datastore */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "persist.h"

/* Helper: append bytes to a growing buffer */
static void buf_append(uint8_t **buf, size_t *len, size_t *cap,
		       const void *data, size_t n)
{
	while (*len + n > *cap) {
		*cap = (*cap == 0) ? 256 : *cap * 2;
		uint8_t *tmp = realloc(*buf, *cap);
		if (!tmp) return;
		*buf = tmp;
	}
	memcpy(*buf + *len, data, n);
	*len += n;
}

static void buf_u8(uint8_t **b, size_t *l, size_t *c, uint8_t v)
{
	buf_append(b, l, c, &v, 1);
}

static void buf_u16(uint8_t **b, size_t *l, size_t *c, uint16_t v)
{
	uint8_t tmp[2] = { v >> 8, v & 0xFF };
	buf_append(b, l, c, tmp, 2);
}

static void buf_u32(uint8_t **b, size_t *l, size_t *c, uint32_t v)
{
	uint8_t tmp[4] = { v >> 24, (v >> 16) & 0xFF,
			   (v >> 8) & 0xFF, v & 0xFF };
	buf_append(b, l, c, tmp, 4);
}

/* Read helpers */
static bool read_u8(const uint8_t **p, size_t *rem, uint8_t *v)
{
	if (*rem < 1) return false;
	*v = **p; (*p)++; (*rem)--;
	return true;
}

static bool read_u16(const uint8_t **p, size_t *rem, uint16_t *v)
{
	if (*rem < 2) return false;
	*v = ((*p)[0] << 8) | (*p)[1];
	*p += 2; *rem -= 2;
	return true;
}

static bool read_u32(const uint8_t **p, size_t *rem, uint32_t *v)
{
	if (*rem < 4) return false;
	*v = ((uint32_t)(*p)[0] << 24) | ((uint32_t)(*p)[1] << 16) |
	     ((uint32_t)(*p)[2] << 8) | (*p)[3];
	*p += 4; *rem -= 4;
	return true;
}

static bool read_bytes(const uint8_t **p, size_t *rem, void *out, size_t n)
{
	if (*rem < n) return false;
	memcpy(out, *p, n);
	*p += n; *rem -= n;
	return true;
}

/* Serialize factory metadata */
size_t ss_persist_serialize_meta(const factory_instance_t *fi, uint8_t **out)
{
	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;

	/* Version byte (2 adds n_tree_nodes) */
	buf_u8(&buf, &len, &cap, 2);

	/* Identity */
	buf_append(&buf, &len, &cap, fi->instance_id, 32);
	buf_append(&buf, &len, &cap, fi->protocol_id, 32);
	buf_u8(&buf, &len, &cap, fi->is_lsp ? 1 : 0);

	/* LSP node ID */
	buf_append(&buf, &len, &cap, fi->lsp_node_id, 33);

	/* Clients */
	buf_u16(&buf, &len, &cap, fi->n_clients);
	for (size_t i = 0; i < fi->n_clients; i++) {
		buf_append(&buf, &len, &cap, fi->clients[i].node_id, 33);
		buf_u8(&buf, &len, &cap, fi->clients[i].signer_slot);
	}

	/* State */
	buf_u8(&buf, &len, &cap, fi->ceremony);
	buf_u32(&buf, &len, &cap, fi->epoch);
	buf_u32(&buf, &len, &cap, fi->max_epochs);
	buf_u8(&buf, &len, &cap, fi->lifecycle);
	buf_u32(&buf, &len, &cap, fi->creation_block);
	buf_u32(&buf, &len, &cap, fi->expiry_block);
	buf_u16(&buf, &len, &cap, fi->early_warning_time);

	/* Funding */
	buf_append(&buf, &len, &cap, fi->funding_txid, 32);
	buf_u32(&buf, &len, &cap, fi->funding_outnum);

	/* v2: tree node count */
	buf_u32(&buf, &len, &cap, fi->n_tree_nodes);

	*out = buf;
	return len;
}

/* Deserialize factory metadata */
bool ss_persist_deserialize_meta(factory_instance_t *fi,
				 const uint8_t *data, size_t len)
{
	const uint8_t *p = data;
	size_t rem = len;
	uint8_t version, tmp8;
	uint16_t tmp16;

	if (!read_u8(&p, &rem, &version) || (version != 1 && version != 2))
		return false;

	if (!read_bytes(&p, &rem, fi->instance_id, 32)) return false;
	if (!read_bytes(&p, &rem, fi->protocol_id, 32)) return false;
	if (!read_u8(&p, &rem, &tmp8)) return false;
	fi->is_lsp = (tmp8 != 0);

	if (!read_bytes(&p, &rem, fi->lsp_node_id, 33)) return false;

	if (!read_u16(&p, &rem, &tmp16)) return false;
	fi->n_clients = tmp16;
	if (fi->n_clients > MAX_FACTORY_PARTICIPANTS) return false;

	for (size_t i = 0; i < fi->n_clients; i++) {
		if (!read_bytes(&p, &rem, fi->clients[i].node_id, 33))
			return false;
		if (!read_u8(&p, &rem, &tmp8)) return false;
		fi->clients[i].signer_slot = tmp8;
	}

	if (!read_u8(&p, &rem, &tmp8)) return false;
	fi->ceremony = tmp8;
	if (!read_u32(&p, &rem, &fi->epoch)) return false;
	if (!read_u32(&p, &rem, &fi->max_epochs)) return false;
	if (!read_u8(&p, &rem, &tmp8)) return false;
	fi->lifecycle = tmp8;
	if (!read_u32(&p, &rem, &fi->creation_block)) return false;
	if (!read_u32(&p, &rem, &fi->expiry_block)) return false;
	if (!read_u16(&p, &rem, &fi->early_warning_time)) return false;

	if (!read_bytes(&p, &rem, fi->funding_txid, 32)) return false;
	if (!read_u32(&p, &rem, &fi->funding_outnum)) return false;

	/* v2 fields */
	if (version >= 2) {
		if (!read_u32(&p, &rem, &fi->n_tree_nodes)) return false;
	}

	return true;
}

/* Serialize channel mappings */
size_t ss_persist_serialize_channels(const factory_instance_t *fi,
				     uint8_t **out)
{
	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;

	buf_u16(&buf, &len, &cap, fi->n_channels);
	for (size_t i = 0; i < fi->n_channels; i++) {
		buf_append(&buf, &len, &cap, fi->channels[i].channel_id, 32);
		buf_u16(&buf, &len, &cap, fi->channels[i].leaf_index);
		buf_u8(&buf, &len, &cap, fi->channels[i].leaf_side);
	}

	*out = buf;
	return len;
}

/* Deserialize channel mappings */
bool ss_persist_deserialize_channels(factory_instance_t *fi,
				     const uint8_t *data, size_t len)
{
	const uint8_t *p = data;
	size_t rem = len;
	uint16_t count, tmp16;
	uint8_t tmp8;

	if (!read_u16(&p, &rem, &count)) return false;
	if (count > MAX_FACTORY_PARTICIPANTS) return false;

	fi->n_channels = count;
	for (size_t i = 0; i < count; i++) {
		if (!read_bytes(&p, &rem, fi->channels[i].channel_id, 32))
			return false;
		if (!read_u16(&p, &rem, &tmp16)) return false;
		fi->channels[i].leaf_index = tmp16;
		if (!read_u8(&p, &rem, &tmp8)) return false;
		fi->channels[i].leaf_side = tmp8;
	}

	return true;
}

/* Serialize breach data */
size_t ss_persist_serialize_breach(const epoch_breach_data_t *bd,
				   uint8_t **out)
{
	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;

	buf_u32(&buf, &len, &cap, bd->epoch);
	buf_u8(&buf, &len, &cap, bd->has_revocation ? 1 : 0);
	if (bd->has_revocation)
		buf_append(&buf, &len, &cap, bd->revocation_secret, 32);
	buf_u32(&buf, &len, &cap, bd->commitment_data_len);
	if (bd->commitment_data_len > 0)
		buf_append(&buf, &len, &cap, bd->commitment_data,
			   bd->commitment_data_len);

	*out = buf;
	return len;
}

/* Deserialize breach data */
bool ss_persist_deserialize_breach(epoch_breach_data_t *bd,
				   const uint8_t *data, size_t len)
{
	const uint8_t *p = data;
	size_t rem = len;
	uint8_t tmp8;
	uint32_t data_len;

	if (!read_u32(&p, &rem, &bd->epoch)) return false;
	if (!read_u8(&p, &rem, &tmp8)) return false;
	bd->has_revocation = (tmp8 != 0);
	if (bd->has_revocation) {
		if (!read_bytes(&p, &rem, bd->revocation_secret, 32))
			return false;
	}
	if (!read_u32(&p, &rem, &data_len)) return false;
	bd->commitment_data_len = data_len;
	if (data_len > 0) {
		if (rem < data_len) return false;
		bd->commitment_data = malloc(data_len);
		memcpy(bd->commitment_data, p, data_len);
		p += data_len; rem -= data_len;
	} else {
		bd->commitment_data = NULL;
	}

	return true;
}

/* Datastore key builders */
static void hex32(const uint8_t *data, char *out)
{
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < 32; i++) {
		out[i * 2] = hex[data[i] >> 4];
		out[i * 2 + 1] = hex[data[i] & 0xF];
	}
	out[64] = '\0';
}

void ss_persist_key_meta(const factory_instance_t *fi, char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/meta", id_hex);
}

void ss_persist_key_channels(const factory_instance_t *fi, char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/channels", id_hex);
}

void ss_persist_key_breach(const factory_instance_t *fi, uint32_t epoch,
			   char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/breach/%u",
		 id_hex, epoch);
}

void ss_persist_key_breach_index(const factory_instance_t *fi, char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/breach-index", id_hex);
}
