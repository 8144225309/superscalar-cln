/* Persistence layer — binary serialization for CLN datastore */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "persist.h"
#include <superscalar/factory.h>

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

	/* Version byte:
	 *   v4 adds factory_pubkeys, allocations, departure
	 *   v5 adds per-client REVOKE-ACK tracking
	 *   v6 adds closed_externally_at_block (watcher Phase 1)
	 *   v7 adds spending_txid + first_noticed_block + closed_by
	 *      (watcher Phase 2a)
	 *   v8 adds dist_signed_txid + breach_epoch + per-epoch kickoff
	 *      signature cache (watcher Phase 2b)
	 *   v9 adds per-epoch state-root TXID cache + signals_observed
	 *      bitmask + state_tx_match_epoch (watcher Phase 3b)
	 *  v10 adds pending_penalties array for fee-bump scheduler
	 *      (watcher Phase 3c) */
	buf_u8(&buf, &len, &cap, 10);

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

	/* v3: full funding info */
	{
		uint8_t amt_bytes[8];
		uint64_t a = fi->funding_amount_sats;
		amt_bytes[0] = (a >> 56) & 0xFF; amt_bytes[1] = (a >> 48) & 0xFF;
		amt_bytes[2] = (a >> 40) & 0xFF; amt_bytes[3] = (a >> 32) & 0xFF;
		amt_bytes[4] = (a >> 24) & 0xFF; amt_bytes[5] = (a >> 16) & 0xFF;
		amt_bytes[6] = (a >>  8) & 0xFF; amt_bytes[7] = a & 0xFF;
		buf_append(&buf, &len, &cap, amt_bytes, 8);
	}
	buf_u8(&buf, &len, &cap, fi->funding_spk_len);
	if (fi->funding_spk_len > 0)
		buf_append(&buf, &len, &cap, fi->funding_spk, fi->funding_spk_len);

	/* v4: client factory pubkeys */
	for (size_t i = 0; i < fi->n_clients; i++) {
		buf_u8(&buf, &len, &cap,
		       fi->clients[i].has_factory_pubkey ? 1 : 0);
		if (fi->clients[i].has_factory_pubkey)
			buf_append(&buf, &len, &cap,
				   fi->clients[i].factory_pubkey, 33);
	}

	/* v4: allocations */
	buf_u8(&buf, &len, &cap, fi->n_allocations);
	for (uint8_t i = 0; i < fi->n_allocations; i++) {
		uint64_t a = fi->allocations[i];
		uint8_t ab[8] = { (a>>56)&0xFF, (a>>48)&0xFF,
				   (a>>40)&0xFF, (a>>32)&0xFF,
				   (a>>24)&0xFF, (a>>16)&0xFF,
				   (a>>8)&0xFF, a&0xFF };
		buf_append(&buf, &len, &cap, ab, 8);
	}

	/* v4: departure state */
	buf_u16(&buf, &len, &cap, fi->n_departed);
	for (size_t i = 0; i < fi->n_clients; i++) {
		buf_u8(&buf, &len, &cap,
		       fi->client_departed[i] ? 1 : 0);
		if (fi->client_departed[i])
			buf_append(&buf, &len, &cap,
				   fi->extracted_keys[i], 32);
	}

	/* v4: our participant index */
	buf_u8(&buf, &len, &cap, (uint8_t)fi->our_participant_idx);

	/* v5: REVOKE-ACK delivery tracking per client. Persists so that a
	 * restart mid-rotation doesn't forget that we owe a resend, and so
	 * that the next rotation's gating can distinguish "client acked"
	 * from "never sent". UINT32_MAX serializes as 0xFFFFFFFF. */
	for (size_t i = 0; i < fi->n_clients; i++) {
		buf_u32(&buf, &len, &cap,
			fi->clients[i].pending_revoke_epoch);
		buf_u32(&buf, &len, &cap,
			fi->clients[i].last_acked_epoch);
	}

	/* v6: closed_externally_at_block. 0 for factories that never went
	 * CLOSED_EXTERNALLY. Paired with the lifecycle byte above for
	 * forensic/reap tooling. */
	buf_u32(&buf, &len, &cap, fi->closed_externally_at_block);

	/* v7: Phase 2a spending-TX identification output. All-zero
	 * spending_txid means "not yet classified" or "scan didn't find it
	 * within the window"; first_noticed_block==0 means "heartbeat has
	 * not fired"; closed_by==CLOSED_BY_UNKNOWN is the safe default. */
	buf_append(&buf, &len, &cap, fi->spending_txid, 32);
	buf_u32(&buf, &len, &cap, fi->first_noticed_block);
	buf_u8(&buf, &len, &cap, fi->closed_by);

	/* v8: Phase 2b classification enrichments. dist_signed_txid is all-
	 * zero when no coop dist TX is signed yet. breach_epoch is
	 * UINT32_MAX sentinel when no breach has been classified. The
	 * history_kickoff_sigs array is (epoch, sig64) tuples captured at
	 * each rotation — used by the classifier to match a published
	 * kickoff's witness sig to the epoch that produced it. */
	buf_append(&buf, &len, &cap, fi->dist_signed_txid, 32);
	buf_u32(&buf, &len, &cap, fi->breach_epoch);
	buf_u32(&buf, &len, &cap, (uint32_t)fi->n_history_kickoff_sigs);
	for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++) {
		buf_u32(&buf, &len, &cap, fi->history_kickoff_epochs[i]);
		buf_append(&buf, &len, &cap, fi->history_kickoff_sigs[i], 64);
	}

	/* v9: Phase 3b. Per-epoch state-root TXIDs (paired with kickoff
	 * sig array above), signals_observed bitmask, state_tx_match_epoch.
	 * The TXID array length equals n_history_kickoff_sigs. */
	for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++)
		buf_append(&buf, &len, &cap,
			   fi->history_state_root_txids[i], 32);
	buf_u8(&buf, &len, &cap, fi->signals_observed);
	buf_u32(&buf, &len, &cap, fi->state_tx_match_epoch);

	/* v10: Phase 3c pending penalties. One u8 count, then for each entry
	 * a packed fixed-size block. Fields chosen to survive process
	 * restarts without needing to rebuild the burn TX — we persist the
	 * txid we broadcast, not the full TX bytes (re-derivable from
	 * breach_data via factory_build_burn_tx). */
	buf_u8(&buf, &len, &cap, (uint8_t)fi->n_pending_penalties);
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		pending_penalty_t *pp = &fi->pending_penalties[i];
		buf_u32(&buf, &len, &cap, pp->epoch);
		/* leaf_index stored as unsigned; negative sentinel as UINT32_MAX */
		buf_u32(&buf, &len, &cap,
			pp->leaf_index < 0 ? UINT32_MAX
					   : (uint32_t)pp->leaf_index);
		buf_append(&buf, &len, &cap, pp->burn_txid, 32);
		{
			uint64_t a = pp->lstock_sats;
			uint8_t ab[8] = { (a>>56)&0xFF, (a>>48)&0xFF,
					   (a>>40)&0xFF, (a>>32)&0xFF,
					   (a>>24)&0xFF, (a>>16)&0xFF,
					   (a>>8)&0xFF, a&0xFF };
			buf_append(&buf, &len, &cap, ab, 8);
		}
		buf_u32(&buf, &len, &cap, pp->csv_unlock_block);
		buf_u32(&buf, &len, &cap, pp->first_broadcast_block);
		buf_u32(&buf, &len, &cap, pp->last_broadcast_block);
		buf_u32(&buf, &len, &cap, pp->confirmed_block);
		{
			uint64_t a = pp->last_feerate;
			uint8_t ab[8] = { (a>>56)&0xFF, (a>>48)&0xFF,
					   (a>>40)&0xFF, (a>>32)&0xFF,
					   (a>>24)&0xFF, (a>>16)&0xFF,
					   (a>>8)&0xFF, a&0xFF };
			buf_append(&buf, &len, &cap, ab, 8);
		}
		buf_u32(&buf, &len, &cap, pp->tx_vsize);
		buf_u8(&buf, &len, &cap, pp->state);
		buf_u8(&buf, &len, &cap, pp->cpfp_attempted);
	}

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

	if (!read_u8(&p, &rem, &version) || version < 1 || version > 9)
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

	/* v3 fields: full funding info */
	if (version >= 3) {
		uint8_t amt_bytes[8];
		if (!read_bytes(&p, &rem, amt_bytes, 8)) return false;
		fi->funding_amount_sats =
			((uint64_t)amt_bytes[0] << 56) |
			((uint64_t)amt_bytes[1] << 48) |
			((uint64_t)amt_bytes[2] << 40) |
			((uint64_t)amt_bytes[3] << 32) |
			((uint64_t)amt_bytes[4] << 24) |
			((uint64_t)amt_bytes[5] << 16) |
			((uint64_t)amt_bytes[6] <<  8) |
			amt_bytes[7];
		uint8_t spk_len;
		if (!read_u8(&p, &rem, &spk_len)) return false;
		fi->funding_spk_len = spk_len;
		if (spk_len > 0 && spk_len <= 34) {
			if (!read_bytes(&p, &rem, fi->funding_spk, spk_len))
				return false;
		}
	}

	/* v4 fields: client pubkeys, allocations, departure */
	if (version >= 4) {
		for (size_t i = 0; i < fi->n_clients; i++) {
			uint8_t has_pk;
			if (!read_u8(&p, &rem, &has_pk)) return false;
			fi->clients[i].has_factory_pubkey = (has_pk != 0);
			if (has_pk) {
				if (!read_bytes(&p, &rem,
						fi->clients[i].factory_pubkey, 33))
					return false;
			}
		}
		uint8_t n_alloc;
		if (!read_u8(&p, &rem, &n_alloc)) return false;
		fi->n_allocations = n_alloc;
		for (uint8_t i = 0; i < n_alloc; i++) {
			uint8_t ab[8];
			if (!read_bytes(&p, &rem, ab, 8)) return false;
			fi->allocations[i] =
				((uint64_t)ab[0]<<56) | ((uint64_t)ab[1]<<48) |
				((uint64_t)ab[2]<<40) | ((uint64_t)ab[3]<<32) |
				((uint64_t)ab[4]<<24) | ((uint64_t)ab[5]<<16) |
				((uint64_t)ab[6]<<8) | ab[7];
		}
		uint16_t n_dep;
		if (!read_u16(&p, &rem, &n_dep)) return false;
		fi->n_departed = n_dep;
		for (size_t i = 0; i < fi->n_clients; i++) {
			uint8_t dep;
			if (!read_u8(&p, &rem, &dep)) return false;
			fi->client_departed[i] = (dep != 0);
			if (dep) {
				if (!read_bytes(&p, &rem,
						fi->extracted_keys[i], 32))
					return false;
			}
		}
		uint8_t pidx;
		if (!read_u8(&p, &rem, &pidx)) return false;
		fi->our_participant_idx = (int)pidx;
	}

	/* Default ack fields: older (v1-v4) meta blobs don't carry them.
	 * UINT32_MAX means "never sent / never acked" — the rotation path
	 * treats that as not-blocking so factories loaded from old blobs
	 * keep working. A fresh REVOKE after upgrade will populate them. */
	for (size_t i = 0; i < fi->n_clients; i++) {
		fi->clients[i].pending_revoke_epoch = UINT32_MAX;
		fi->clients[i].last_acked_epoch = UINT32_MAX;
	}

	if (version >= 5) {
		for (size_t i = 0; i < fi->n_clients; i++) {
			uint32_t pe, la;
			if (!read_u32(&p, &rem, &pe)) return false;
			if (!read_u32(&p, &rem, &la)) return false;
			fi->clients[i].pending_revoke_epoch = pe;
			fi->clients[i].last_acked_epoch = la;
		}
	}

	/* v6: closed_externally_at_block. Older blobs default to 0, which is
	 * also the sentinel for "never externally closed" — so no special
	 * handling is needed for pre-v6 records. */
	fi->closed_externally_at_block = 0;
	if (version >= 6) {
		if (!read_u32(&p, &rem, &fi->closed_externally_at_block))
			return false;
	}

	/* v7: Phase 2a classification output. Pre-v7 blobs default to
	 * zero spending_txid and CLOSED_BY_UNKNOWN. Existing CLOSED_EXTERNALLY
	 * records from Phase 1 will read as unclassified — the operator can
	 * re-trigger classification via factory-scan-external-close. */
	memset(fi->spending_txid, 0, 32);
	fi->first_noticed_block = 0;
	fi->closed_by = CLOSED_BY_UNKNOWN;
	if (version >= 7) {
		if (!read_bytes(&p, &rem, fi->spending_txid, 32))
			return false;
		if (!read_u32(&p, &rem, &fi->first_noticed_block))
			return false;
		uint8_t cb;
		if (!read_u8(&p, &rem, &cb))
			return false;
		fi->closed_by = cb;
	}

	/* v8: Phase 2b classification enrichments. Pre-v8 blobs default to
	 * all-zero dist_signed_txid, UINT32_MAX breach_epoch, and an empty
	 * kickoff-sig cache. Factories without cached sigs can still match
	 * coop close via a later dist_signed_txid compute, but breach-vs-
	 * normal-exit for rotations that happened before the upgrade is
	 * structurally unreachable — those signatures weren't captured at
	 * rotation time. */
	memset(fi->dist_signed_txid, 0, 32);
	fi->breach_epoch = UINT32_MAX;
	fi->n_history_kickoff_sigs = 0;
	if (version >= 8) {
		if (!read_bytes(&p, &rem, fi->dist_signed_txid, 32))
			return false;
		if (!read_u32(&p, &rem, &fi->breach_epoch))
			return false;
		uint32_t n_sigs;
		if (!read_u32(&p, &rem, &n_sigs))
			return false;
		if (n_sigs > MAX_HISTORY_SIGS)
			return false;
		for (uint32_t i = 0; i < n_sigs; i++) {
			if (!read_u32(&p, &rem,
				      &fi->history_kickoff_epochs[i]))
				return false;
			if (!read_bytes(&p, &rem,
					fi->history_kickoff_sigs[i], 64))
				return false;
		}
		fi->n_history_kickoff_sigs = n_sigs;
	}

	/* v9: Phase 3b. State-root TXIDs (one per cached kickoff sig
	 * epoch), signals_observed bitmask, state_tx_match_epoch. Pre-v9
	 * blobs default to all-zero TXIDs, no signals, UINT32_MAX match. */
	memset(fi->history_state_root_txids, 0,
	       sizeof(fi->history_state_root_txids));
	fi->signals_observed = 0;
	fi->state_tx_match_epoch = UINT32_MAX;
	if (version >= 9) {
		for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++) {
			if (!read_bytes(&p, &rem,
					fi->history_state_root_txids[i], 32))
				return false;
		}
		uint8_t sig_bits;
		if (!read_u8(&p, &rem, &sig_bits))
			return false;
		fi->signals_observed = sig_bits;
		if (!read_u32(&p, &rem, &fi->state_tx_match_epoch))
			return false;
	}

	/* v10: Phase 3c pending penalties. Pre-v10 blobs default to empty;
	 * the scheduler will just no-op on empty arrays. */
	fi->n_pending_penalties = 0;
	memset(fi->pending_penalties, 0, sizeof(fi->pending_penalties));
	if (version >= 10) {
		uint8_t n_pen;
		if (!read_u8(&p, &rem, &n_pen))
			return false;
		if (n_pen > MAX_PENDING_PENALTIES)
			return false;
		for (uint8_t i = 0; i < n_pen; i++) {
			pending_penalty_t *pp = &fi->pending_penalties[i];
			uint32_t leaf_u32;
			if (!read_u32(&p, &rem, &pp->epoch)) return false;
			if (!read_u32(&p, &rem, &leaf_u32)) return false;
			pp->leaf_index = (leaf_u32 == UINT32_MAX)
				? -1 : (int32_t)leaf_u32;
			if (!read_bytes(&p, &rem, pp->burn_txid, 32))
				return false;
			{
				uint8_t ab[8];
				if (!read_bytes(&p, &rem, ab, 8)) return false;
				pp->lstock_sats =
					((uint64_t)ab[0] << 56) |
					((uint64_t)ab[1] << 48) |
					((uint64_t)ab[2] << 40) |
					((uint64_t)ab[3] << 32) |
					((uint64_t)ab[4] << 24) |
					((uint64_t)ab[5] << 16) |
					((uint64_t)ab[6] <<  8) |
					 (uint64_t)ab[7];
			}
			if (!read_u32(&p, &rem, &pp->csv_unlock_block))
				return false;
			if (!read_u32(&p, &rem, &pp->first_broadcast_block))
				return false;
			if (!read_u32(&p, &rem, &pp->last_broadcast_block))
				return false;
			if (!read_u32(&p, &rem, &pp->confirmed_block))
				return false;
			{
				uint8_t ab[8];
				if (!read_bytes(&p, &rem, ab, 8)) return false;
				pp->last_feerate =
					((uint64_t)ab[0] << 56) |
					((uint64_t)ab[1] << 48) |
					((uint64_t)ab[2] << 40) |
					((uint64_t)ab[3] << 32) |
					((uint64_t)ab[4] << 24) |
					((uint64_t)ab[5] << 16) |
					((uint64_t)ab[6] <<  8) |
					 (uint64_t)ab[7];
			}
			if (!read_u32(&p, &rem, &pp->tx_vsize)) return false;
			if (!read_u8(&p, &rem, &pp->state)) return false;
			if (!read_u8(&p, &rem, &pp->cpfp_attempted))
				return false;
		}
		fi->n_pending_penalties = n_pen;
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

void ss_persist_key_signed_txs(const factory_instance_t *fi, char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/signed_txs", id_hex);
}

/* Serialize signed DW tree transactions.
 * Only includes nodes where is_signed and signed_tx.data exist. */
size_t ss_persist_serialize_signed_txs(const void *lib_factory,
                                       uint8_t **out)
{
	const factory_t *f = (const factory_t *)lib_factory;
	if (!f) { *out = NULL; return 0; }

	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;
	uint16_t count = 0;

	/* Count signed nodes */
	for (size_t ni = 0; ni < f->n_nodes; ni++) {
		if (f->nodes[ni].is_signed &&
		    f->nodes[ni].signed_tx.data &&
		    f->nodes[ni].signed_tx.len > 0)
			count++;
	}

	buf_u16(&buf, &len, &cap, count);

	for (size_t ni = 0; ni < f->n_nodes; ni++) {
		if (!f->nodes[ni].is_signed ||
		    !f->nodes[ni].signed_tx.data ||
		    f->nodes[ni].signed_tx.len == 0)
			continue;

		buf_u16(&buf, &len, &cap, (uint16_t)ni);
		buf_append(&buf, &len, &cap, f->nodes[ni].txid, 32);
		buf_u32(&buf, &len, &cap, (uint32_t)f->nodes[ni].signed_tx.len);
		buf_append(&buf, &len, &cap,
			   f->nodes[ni].signed_tx.data,
			   f->nodes[ni].signed_tx.len);
	}

	*out = buf;
	return len;
}

/* Deserialize signed TXs into a rebuilt factory_t. */
bool ss_persist_deserialize_signed_txs(void *lib_factory,
                                       const uint8_t *data, size_t len)
{
	factory_t *f = (factory_t *)lib_factory;
	if (!f || !data) return false;

	const uint8_t *p = data;
	size_t rem = len;
	uint16_t count;

	if (!read_u16(&p, &rem, &count)) return false;

	for (uint16_t i = 0; i < count; i++) {
		uint16_t ni;
		uint32_t tx_len;

		if (!read_u16(&p, &rem, &ni)) return false;
		if (ni >= f->n_nodes) return false;

		if (!read_bytes(&p, &rem, f->nodes[ni].txid, 32))
			return false;
		if (!read_u32(&p, &rem, &tx_len)) return false;
		if (rem < tx_len) return false;

		/* Allocate and copy signed TX data */
		if (f->nodes[ni].signed_tx.data)
			free(f->nodes[ni].signed_tx.data);
		f->nodes[ni].signed_tx.data = malloc(tx_len);
		if (!f->nodes[ni].signed_tx.data) return false;
		memcpy(f->nodes[ni].signed_tx.data, p, tx_len);
		f->nodes[ni].signed_tx.len = tx_len;
		f->nodes[ni].signed_tx.cap = tx_len;
		f->nodes[ni].is_signed = true;

		p += tx_len;
		rem -= tx_len;
	}

	return true;
}

void ss_persist_key_dist_tx(const factory_instance_t *fi, char *out, size_t len)
{
	char id_hex[65];
	hex32(fi->instance_id, id_hex);
	snprintf(out, len, "superscalar/factories/%s/dist_tx", id_hex);
}

/* Serialize signed distribution TX.
 * Format: tx_len(u32) + tx_data(tx_len) */
size_t ss_persist_serialize_dist_tx(const factory_instance_t *fi,
                                    uint8_t **out)
{
	if (!fi->dist_signed_tx || fi->dist_signed_tx_len == 0) {
		*out = NULL;
		return 0;
	}

	uint8_t *buf = NULL;
	size_t len = 0, cap = 0;

	buf_u32(&buf, &len, &cap, (uint32_t)fi->dist_signed_tx_len);
	buf_append(&buf, &len, &cap, fi->dist_signed_tx, fi->dist_signed_tx_len);

	*out = buf;
	return len;
}

/* Deserialize signed distribution TX */
bool ss_persist_deserialize_dist_tx(factory_instance_t *fi,
                                    const uint8_t *data, size_t len)
{
	const uint8_t *p = data;
	size_t rem = len;
	uint32_t tx_len;

	if (!read_u32(&p, &rem, &tx_len)) return false;
	if (rem < tx_len) return false;

	free(fi->dist_signed_tx);
	fi->dist_signed_tx = malloc(tx_len);
	if (!fi->dist_signed_tx) return false;
	memcpy(fi->dist_signed_tx, p, tx_len);
	fi->dist_signed_tx_len = tx_len;

	return true;
}
