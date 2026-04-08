/* SuperScalar channel factory plugin for Core Lightning.
 *
 * Links against libsuperscalar.a for DW tree construction,
 * MuSig2 signing, and factory state management.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include <bitcoin/psbt.h>
#include <bitcoin/privkey.h>
#include <common/features.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ccan/crypto/sha256/sha256.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "ceremony.h"
#include "factory_state.h"
#include "nonce_exchange.h"
#include "persist.h"

/* SuperScalar library */
#include <superscalar/factory.h>
#include <superscalar/musig.h>
#include <superscalar/dw_state.h>

static struct plugin *plugin_handle;
static superscalar_state_t ss_state;
static secp256k1_context *global_secp_ctx;


/* bLIP-56 factory message type */
#define FACTORY_MSG_TYPE	32800

/* bLIP-56 feature bit (may already be in common/features.h) */
#ifndef OPT_PLUGGABLE_CHANNEL_FACTORIES
#define OPT_PLUGGABLE_CHANNEL_FACTORIES 271
#endif

/* bLIP-56 standard submessage IDs */
#define BLIP56_SUBMSG_SUPPORTED_PROTOCOLS	2
#define BLIP56_SUBMSG_FACTORY_PIGGYBACK		4

/* Configurable factory parameters */
#define DEFAULT_FUNDING_SATS		500000	   /* Per-channel funding amount */
#define DEFAULT_FACTORY_FUNDING_SATS	1000000	   /* Total factory funding */
#define DW_STEP_BLOCKS			144	   /* Blocks between DW states (~1 day) */
#define DIST_TX_LOCKTIME_DAYS		90	   /* nLockTime for distribution TX */
#define MAX_DIST_OUTPUTS		65	   /* Max outputs in distribution TX */
#define MAX_WIRE_BUF			32768	   /* Wire message buffer size */

/* SuperScalar protocol ID: first 32 bytes of "SuperScalar/v1" zero-padded */
static const uint8_t SUPERSCALAR_PROTOCOL_ID[32] = {
	'S','u','p','e','r','S','c','a','l','a','r','/','v','1',
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* Derive a deterministic seckey from instance_id + participant index.
 * When HSM-derived master key is available, uses HMAC-SHA256 for
 * proper key derivation. Falls back to demo XOR otherwise.
 * NOTE: Only our OWN seckey uses the HSM path. Other participants'
 * pubkeys come from their actual node keys exchanged during setup. */
static void derive_factory_seckey(unsigned char seckey[32],
				  const uint8_t instance_id[32],
				  int participant_idx)
{
	if (ss_state.has_master_key) {
		/* HMAC-SHA256(master_key, instance_id || idx) */
		unsigned char hmac_input[34];
		memcpy(hmac_input, instance_id, 32);
		hmac_input[32] = (uint8_t)(participant_idx & 0xFF);
		hmac_input[33] = (uint8_t)((participant_idx >> 8) & 0xFF);

		/* Use secp256k1's nonce_function_rfc6979 as HMAC proxy:
		 * We XOR master_key with input through SHA256 for now.
		 * A proper HMAC would use openssl/libsodium. */
		struct sha256 hash;
		struct sha256_ctx sctx;
		sha256_init(&sctx);
		sha256_update(&sctx, ss_state.factory_master_key, 32);
		sha256_update(&sctx, hmac_input, sizeof(hmac_input));
		sha256_done(&sctx, &hash);
		memcpy(seckey, hash.u.u8, 32);
	} else {
		/* Demo fallback: XOR instance_id with participant index */
		memcpy(seckey, instance_id, 32);
		seckey[0] ^= (uint8_t)(participant_idx & 0xFF);
		seckey[1] ^= (uint8_t)((participant_idx >> 8) & 0xFF);
	}
	/* Ensure valid seckey (nonzero, well below curve order) */
	if (seckey[0] == 0) seckey[0] = 0x01;
}

/* Forward declarations for RPC callbacks */
static struct command_result *rpc_done(struct command *cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *arg);
static struct command_result *rpc_err(struct command *cmd,
				      const char *method,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg);

/* Per-client context for async fundchannel_start → fundchannel_complete chain.
 * Carries the factory pointer and the specific client index so callbacks
 * know which peer they're completing with. */
struct open_channel_ctx {
	factory_instance_t *fi;
	size_t client_idx;
};

/* Send a SuperScalar message wrapped in factory_piggyback (submsg 4).
 * Wire format: type(2) + submsg_id=4(2) + TLV[0]=protocol_id(34) +
 *              TLV[1024]=payload(4+len) where payload = ss_submsg(2)+data */
static void send_factory_msg(struct command *cmd, const char *peer_id,
			     uint16_t ss_submsg, const uint8_t *data,
			     size_t data_len)
{
	/* Build factory_piggyback TLV payload:
	 * TLV type 0: protocol_id (1+1+32 = 34 bytes)
	 * TLV type 1024: header(3) + varint_len(1 or 3) + ss_submsg(2) + data */
	size_t inner_len = 2 + data_len; /* ss_submsg(2) + data */
	size_t varint_size = (inner_len < 253) ? 1 : 3;
	size_t tlv1024_len = 3 + varint_size + inner_len;
	size_t wire_len = 4 + 34 + tlv1024_len;

	uint8_t *wire = calloc(1, wire_len);
	wire[0] = 0x80; wire[1] = 0x20; /* type 32800 */
	wire[2] = 0x00; wire[3] = 0x04; /* submsg 4 = factory_piggyback */

	uint8_t *p = wire + 4;
	/* TLV type 0: factory_protocol_id */
	*p++ = 0x00; /* type */
	*p++ = 32;   /* length */
	memcpy(p, SUPERSCALAR_PROTOCOL_ID, 32); p += 32;

	/* TLV type 1024 (0x0400): factory_piggyback_payload */
	*p++ = 0xfd; /* varint prefix for 2-byte type */
	*p++ = 0x04; *p++ = 0x00; /* type 1024 */
	/* length as varint */
	if (inner_len < 253) {
		*p++ = (uint8_t)inner_len;
	} else {
		*p++ = 0xfd;
		*p++ = (inner_len >> 8) & 0xFF;
		*p++ = inner_len & 0xFF;
	}
	/* SuperScalar submessage ID */
	*p++ = (ss_submsg >> 8) & 0xFF;
	*p++ = ss_submsg & 0xFF;
	/* Data */
	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;

	size_t actual_len = (size_t)(p - wire);
	char *hex = tal_arr(cmd, char, actual_len * 2 + 1);
	for (size_t h = 0; h < actual_len; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err, cmd);
	json_add_string(req->js, "node_id", peer_id);
	json_add_string(req->js, "msg", hex);
	send_outreq(req);
	free(wire);
}

/* Send supported_factory_protocols (submsg 2) to a peer.
 * TLV type 512: list of 32-byte protocol IDs we support. */
static void send_supported_protocols(struct command *cmd, const char *peer_id)
{
	/* Wire: type(2)+submsg(2) + TLV[512](4+32=36 bytes) = 40 total */
	uint8_t wire[40];
	wire[0] = 0x80; wire[1] = 0x20; /* type 32800 */
	wire[2] = 0x00; wire[3] = 0x02; /* submsg 2 = supported_factory_protocols */

	/* TLV type 512 (0x0200): protocol_ids */
	wire[4] = 0xfd; /* varint prefix for 2-byte type */
	wire[5] = 0x02; wire[6] = 0x00; /* type 512 */
	wire[7] = 32; /* length: 1 protocol * 32 bytes */
	memcpy(wire + 8, SUPERSCALAR_PROTOCOL_ID, 32);

	char hex[81]; /* (4+36)*2 + 1 */
	for (size_t h = 0; h < 40; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err, cmd);
	json_add_string(req->js, "node_id", peer_id);
	json_add_string(req->js, "msg", hex);
	send_outreq(req);

	plugin_log(plugin_handle, LOG_DBG,
		   "Sent supported_factory_protocols to %s", peer_id);
}

/* Ceremony state is now per-factory in ss_state */

/* Generic RPC callback — just log and ignore result */
static struct command_result *rpc_done(struct command *cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *arg)
{
	return command_still_pending(cmd);
}

static struct command_result *rpc_err(struct command *cmd,
				      const char *method,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg)
{
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	if (msg_tok) {
		const char *errmsg = json_strdup(cmd, buf, msg_tok);
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "RPC %s failed: %s", method,
			   errmsg ? errmsg : "(null)");
	} else {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "RPC %s failed (no message)", method);
	}
	return command_still_pending(cmd);
}

/* Callback after fundchannel_complete succeeds */
static struct command_result *fundchannel_complete_ok(struct command *cmd,
						      const char *method,
						      const char *buf,
						      const jsmntok_t *result,
						      void *arg)
{
	struct open_channel_ctx *ctx = (struct open_channel_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	size_t ci = ctx->client_idx;
	const jsmntok_t *cid_tok;

	cid_tok = json_get_member(buf, result, "channel_id");
	if (cid_tok) {
		const char *cid_hex = json_strdup(cmd, buf, cid_tok);
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory channel opened for client %zu: "
			   "channel_id=%s", ci, cid_hex ? cid_hex : "?");

		/* Map channel to factory leaf.
		 * leaf_index = client index (each client gets one leaf). */
		if (cid_hex && strlen(cid_hex) == 64) {
			uint8_t cid[32];
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				sscanf(cid_hex + j*2, "%02x", &b);
				cid[j] = (uint8_t)b;
			}
			ss_factory_map_channel(fi, cid, (int)ci, 0);
		}
	}

	fi->lifecycle = FACTORY_LIFECYCLE_ACTIVE;
	ss_save_factory(cmd, fi);
	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory lifecycle=active, n_channels=%zu",
		   fi->n_channels);

	return command_still_pending(cmd);
}

/* Callback after fundchannel_start succeeds — build PSBT, call complete */
static struct command_result *fundchannel_start_ok(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct open_channel_ctx *ctx = (struct open_channel_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	size_t ci = ctx->client_idx;
	const jsmntok_t *spk_tok;

	spk_tok = json_get_member(buf, result, "scriptpubkey");
	if (!spk_tok) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "fundchannel_start: no scriptpubkey in response");
		return command_still_pending(cmd);
	}

	/* Parse scriptpubkey from hex */
	const char *spk_hex = json_strdup(cmd, buf, spk_tok);
	size_t spk_hex_len = spk_hex ? strlen(spk_hex) : 0;
	size_t spk_len = spk_hex_len / 2;
	u8 *spk = tal_arr(cmd, u8, spk_len);
	for (size_t i = 0; i < spk_len; i++) {
		unsigned int b;
		sscanf(spk_hex + i*2, "%02x", &b);
		spk[i] = (uint8_t)b;
	}

	/* Funding amount: half of factory total for 2 participants (demo) */
	struct amount_sat funding_amt;
	funding_amt.satoshis = DEFAULT_FUNDING_SATS;

	plugin_log(plugin_handle, LOG_INFORM,
		   "fundchannel_start ok for client %zu, building PSBT "
		   "(spk=%s, amt=%"PRIu64")",
		   ci, spk_hex, funding_amt.satoshis);

	/* Build minimal PSBT: 0 inputs, 1 output matching funding script */
	struct wally_psbt *psbt = create_psbt(cmd, 0, 0, 0);
	psbt_append_output(psbt, spk, funding_amt);

	/* Get the peer node_id for this specific client */
	char nid[67];
	for (int j = 0; j < 33; j++)
		sprintf(nid + j*2, "%02x", fi->clients[ci].node_id[j]);
	nid[66] = '\0';

	/* Call fundchannel_complete with the PSBT */
	struct out_req *req = jsonrpc_request_start(cmd,
		"fundchannel_complete",
		fundchannel_complete_ok, rpc_err, ctx);
	json_add_string(req->js, "id", nid);
	json_add_psbt(req->js, "psbt", psbt);
	send_outreq(req);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Called fundchannel_complete for client %zu (%s)",
		   ci, nid);

	return command_still_pending(cmd);
}

/* Open factory channels for each client.
 * Called from factory-open-channels RPC (separate cmd context). */
static void open_factory_channels(struct command *cmd,
				   factory_instance_t *fi)
{
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';

		char proto_hex[65], inst_hex[65];
		for (int j = 0; j < 32; j++) {
			sprintf(proto_hex + j*2, "%02x",
				SUPERSCALAR_PROTOCOL_ID[j]);
			sprintf(inst_hex + j*2, "%02x",
				fi->instance_id[j]);
		}

		struct open_channel_ctx *ctx = tal(cmd, struct open_channel_ctx);
		ctx->fi = fi;
		ctx->client_idx = ci;

		struct out_req *req = jsonrpc_request_start(cmd,
			"fundchannel_start",
			fundchannel_start_ok, rpc_err, ctx);
		json_add_string(req->js, "id", nid);
		{
			char amt_str[32];
			snprintf(amt_str, sizeof(amt_str), "%usat",
				 DEFAULT_FUNDING_SATS);
			json_add_string(req->js, "amount", amt_str);
		}
		json_add_bool(req->js, "announce", false);
		json_add_u32(req->js, "mindepth", 0);
		json_add_string(req->js, "factory_protocol_id", proto_hex);
		json_add_string(req->js, "factory_instance_id", inst_hex);
		json_add_u64(req->js, "factory_early_warning_time", 6);
		send_outreq(req);

		plugin_log(plugin_handle, LOG_INFORM,
			   "Opening factory channel with client %zu (%s)",
			   ci, nid);
	}
}

/* Complete rotation: send REVOKE for old epoch, ROTATE_COMPLETE,
 * and trigger factory-change on open channels. Called after both
 * rotation tree and distribution TX are signed. */
static void rotate_finish_and_notify(struct command *cmd,
				     factory_instance_t *fi)
{
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f) return;

	fi->ceremony = CEREMONY_ROTATE_COMPLETE;
	fi->rotation_in_progress = false;

	/* Send revocation secret for old epoch */
	uint32_t old_ep = fi->epoch - 1;
	unsigned char rev_secret[32];
	if (factory_get_revocation_secret(f, old_ep, rev_secret)) {
		uint8_t rev_payload[36];
		rev_payload[0] = (old_ep >> 24) & 0xFF;
		rev_payload[1] = (old_ep >> 16) & 0xFF;
		rev_payload[2] = (old_ep >> 8) & 0xFF;
		rev_payload[3] = old_ep & 0xFF;
		memcpy(rev_payload + 4, rev_secret, 32);

		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			char nid[67];
			for (int j = 0; j < 33; j++)
				sprintf(nid + j*2, "%02x",
					fi->clients[ci].node_id[j]);
			nid[66] = '\0';
			send_factory_msg(cmd, nid,
				SS_SUBMSG_REVOKE, rev_payload, 36);
		}
		plugin_log(plugin_handle, LOG_INFORM,
			   "LSP: sent REVOKE for epoch %u", old_ep);
	}

	/* Send ROTATE_COMPLETE to clients */
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';
		send_factory_msg(cmd, nid,
			SS_SUBMSG_ROTATE_COMPLETE,
			fi->instance_id, 32);
	}

	/* Trigger factory-change on open channels */
	if (fi->n_channels > 0) {
		for (size_t ch = 0; ch < fi->n_channels; ch++) {
			char cid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(cid_hex + j*2, "%02x",
					fi->channels[ch].channel_id[j]);

			char txid_hex[65];
			size_t leaf_idx = fi->channels[ch].leaf_index;
			if (leaf_idx < f->n_nodes) {
				for (int j = 0; j < 32; j++)
					sprintf(txid_hex + j*2, "%02x",
						f->nodes[leaf_idx].txid[31-j]);
			} else {
				memset(txid_hex, '0', 64);
			}
			txid_hex[64] = '\0';

			struct out_req *creq = jsonrpc_request_start(
				cmd, "factory-change",
				rpc_done, rpc_err, fi);
			json_add_string(creq->js, "channel_id", cid_hex);
			json_add_string(creq->js, "new_funding_txid", txid_hex);
			json_add_u32(creq->js, "new_funding_outnum", 0);
			send_outreq(creq);

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: triggered factory-change on channel %zu",
				   ch);
		}
	}

	ss_save_factory(cmd, fi);

	plugin_log(plugin_handle, LOG_INFORM,
		   "LSP: ROTATION COMPLETE epoch=%u", fi->epoch);
}

/* Persist a factory's state to CLN datastore (fire-and-forget) */
static void ss_save_factory(struct command *cmd, factory_instance_t *fi)
{
	char key[128];
	uint8_t *buf;
	size_t len;

	/* Save metadata */
	ss_persist_key_meta(fi, key, sizeof(key));
	len = ss_persist_serialize_meta(fi, &buf);
	if (len > 0 && buf) {
		jsonrpc_set_datastore_binary(cmd, key, buf, len,
			"create-or-replace", NULL, NULL, NULL);
		free(buf);
	}

	/* Save channel mappings */
	if (fi->n_channels > 0) {
		ss_persist_key_channels(fi, key, sizeof(key));
		len = ss_persist_serialize_channels(fi, &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", NULL, NULL, NULL);
			free(buf);
		}
	}

	/* Save breach data for current epoch */
	for (size_t i = 0; i < fi->n_breach_epochs; i++) {
		ss_persist_key_breach(fi, fi->breach_data[i].epoch,
				      key, sizeof(key));
		len = ss_persist_serialize_breach(&fi->breach_data[i], &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", NULL, NULL, NULL);
			free(buf);
		}
	}

	plugin_log(plugin_handle, LOG_DBG,
		   "Persisted factory state (epoch=%u, channels=%zu)",
		   fi->epoch, fi->n_channels);
}

/* Load factories from CLN datastore on startup.
 * Uses rpc_scan_datastore_hex to read each factory's metadata. */
static void ss_load_factories(struct command *cmd)
{
	/* List all datastore entries under superscalar/factories/ */
	struct out_req *req = jsonrpc_request_start(cmd,
		"listdatastore", rpc_done, rpc_err, NULL);
	json_add_string(req->js, "key",
		"superscalar/factories");
	send_outreq(req);

	/* Note: full async load would parse the listdatastore result
	 * and deserialize each factory. For now, factories start fresh
	 * on restart — the datastore entries serve as a recovery
	 * mechanism that can be read by factory-list or a recovery RPC. */
	plugin_log(plugin_handle, LOG_INFORM,
		   "Queried datastore for persisted factories");
}

/* Dispatch SuperScalar protocol submessages.
 * Data format: [32 bytes instance_id][payload] */
static void dispatch_superscalar_submsg(struct command *cmd,
					const char *peer_id,
					u16 submsg_id,
					const u8 *data, size_t len)
{
	factory_instance_t *fi = NULL;

	/* Extract instance_id from submessage (first 32 bytes).
	 * Don't strip it — handlers that use nonce_bundle_deserialize
	 * expect the full payload including instance_id. */
	if (len >= 32 && submsg_id != SS_SUBMSG_FACTORY_PROPOSE
	    && submsg_id != SS_SUBMSG_ROTATE_PROPOSE
	    && submsg_id != SS_SUBMSG_REVOKE
	    && submsg_id != SS_SUBMSG_CLOSE_PROPOSE) {
		fi = ss_factory_find(&ss_state, data);
		if (!fi) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Unknown factory instance in submsg 0x%04x from %s",
				   submsg_id, peer_id);
			return;
		}
		/* data and len unchanged — handler gets full payload */
	}

	switch (submsg_id) {
	case SS_SUBMSG_FACTORY_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client side: deserialize nonce bundle, init factory,
		 * generate our nonces, respond with NONCE_BUNDLE. */
		{
			nonce_bundle_t nb;
			if (!nonce_bundle_deserialize(&nb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad FACTORY_PROPOSE payload");
				break;
			}

			fi = ss_factory_new(&ss_state, nb.instance_id);
			if (!fi) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Failed to create factory");
				break;
			}
			fi->is_lsp = false;

			/* Store LSP peer_id as node_id */
			if (strlen(peer_id) == 66) {
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					fi->lsp_node_id[j] = (uint8_t)b;
				}
			}

			/* Use pubkeys from the bundle (same as LSP's) */
			secp256k1_context *ctx = global_secp_ctx;
			secp256k1_pubkey *pubkeys = calloc(nb.n_participants,
				sizeof(secp256k1_pubkey));

			for (uint32_t pk = 0; pk < nb.n_participants; pk++) {
				if (!secp256k1_ec_pubkey_parse(ctx,
					&pubkeys[pk],
					nb.pubkeys[pk], 33)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Bad pubkey %u in propose", pk);
					free(pubkeys);
					break;
				}
			}

			/* Derive our keypair deterministically from instance_id.
			 * We're participant 1 (first client). */
			unsigned char our_sec[32];
			int our_idx = 1;
			derive_factory_seckey(our_sec, nb.instance_id, our_idx);

			/* Init and build tree with LSP's pubkeys */
			factory_t *factory = calloc(1, sizeof(factory_t));
			factory_init_from_pubkeys(factory, ctx,
				pubkeys, nb.n_participants,
				DW_STEP_BLOCKS, 16);
			if (nb.n_participants <= 2)
				factory_set_arity(factory, FACTORY_ARITY_1);
			else
				factory_set_arity(factory, FACTORY_ARITY_2);

			uint8_t synth_txid[32], synth_spk[34];
			for (int j = 0; j < 32; j++) synth_txid[j] = j + 1;
			synth_spk[0] = 0x51; synth_spk[1] = 0x20;
			memset(synth_spk + 2, 0xAA, 32);
			factory_set_funding(factory, synth_txid, 0,
					    DEFAULT_FACTORY_FUNDING_SATS,
					    synth_spk, 34);

			if (!factory_build_tree(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: factory_build_tree failed");
				free(factory);
				free(pubkeys);
				break;
			}
			factory_sessions_init(factory);
			fi->lib_factory = factory;

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: tree built, %zu nodes",
				   (size_t)factory->n_nodes);

			/* Set LSP nonces on our sessions */
			for (size_t e = 0; e < nb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					nb.entries[e].pubnonce);
				factory_session_set_nonce(factory,
					nb.entries[e].node_idx,
					nb.entries[e].signer_slot,
					&pn);
			}

			/* Generate our nonces */
			size_t our_node_count =
				factory_count_nodes_for_participant(factory,
								   our_idx);
			/* Heap-allocate pool so secnonces survive this scope */
			musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool,
				our_node_count, our_sec,
				&pubkeys[our_idx], NULL);

			/* Store pool, seckey, participant index for signing */
			fi->nonce_pool = pool;
			memcpy(fi->our_seckey, our_sec, 32);
			fi->our_participant_idx = our_idx;
			fi->n_secnonces = 0;

			nonce_bundle_t resp;
			memset(&resp, 0, sizeof(resp));
			memcpy(resp.instance_id, fi->instance_id, 32);
			resp.n_participants = nb.n_participants;
			resp.n_nodes = factory->n_nodes;
			resp.n_entries = 0;

			size_t pool_entry = 0;
			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *sec;
				secp256k1_musig_pubnonce pub;
				if (!musig_nonce_pool_next(pool, &sec, &pub))
					break;

				/* Record which pool index maps to which node */
				fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
				fi->secnonce_node_idx[fi->n_secnonces] = ni;
				fi->n_secnonces++;
				pool_entry++;

				factory_session_set_nonce(factory, ni,
							  (size_t)slot, &pub);
				musig_pubnonce_serialize(ctx,
					resp.entries[resp.n_entries].pubnonce,
					&pub);
				resp.entries[resp.n_entries].node_idx = ni;
				resp.entries[resp.n_entries].signer_slot = slot;
				resp.n_entries++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: generated %zu nonce entries",
				   resp.n_entries);

			/* Serialize and send NONCE_BUNDLE back to LSP */
			uint8_t rbuf[MAX_WIRE_BUF];
			size_t rlen = nonce_bundle_serialize(&resp,
				rbuf, sizeof(rbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_NONCE_BUNDLE,
					 rbuf, rlen);

			/* Client can finalize immediately — has all nonces */
			if (!factory_sessions_finalize(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: factory_sessions_finalize failed");
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: nonces finalized");

				/* Create partial sigs and send PSIG_BUNDLE */
				secp256k1_keypair kp;
				if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Client: keypair create failed");
				} else {
					nonce_bundle_t psig_nb;
					memset(&psig_nb, 0, sizeof(psig_nb));
					memcpy(psig_nb.instance_id, fi->instance_id, 32);
					psig_nb.n_participants = nb.n_participants;
					psig_nb.n_nodes = factory->n_nodes;
					psig_nb.n_entries = 0;

					/* Use stored secnonces from heap-allocated pool */
					musig_nonce_pool_t *sp =
						(musig_nonce_pool_t *)fi->nonce_pool;

					for (size_t si = 0; si < fi->n_secnonces; si++) {
						uint32_t pi = fi->secnonce_pool_idx[si];
						uint32_t ni = fi->secnonce_node_idx[si];
						secp256k1_musig_secnonce *sn =
							&sp->nonces[pi].secnonce;

						int slot = factory_find_signer_slot(
							factory, ni, fi->our_participant_idx);
						if (slot < 0) continue;

						secp256k1_musig_partial_sig psig;
						if (!musig_create_partial_sig(
							ctx, &psig, sn, &kp,
							&factory->nodes[ni].signing_session)) {
							plugin_log(plugin_handle, LOG_BROKEN,
								   "Client: partial_sig failed node %u", ni);
							continue;
						}

						musig_partial_sig_serialize(ctx,
							psig_nb.entries[psig_nb.n_entries].pubnonce,
							&psig);
						psig_nb.entries[psig_nb.n_entries].node_idx = ni;
						psig_nb.entries[psig_nb.n_entries].signer_slot = slot;
						psig_nb.n_entries++;
					}

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: created %zu partial sigs",
						   psig_nb.n_entries);

					/* Send PSIG_BUNDLE to LSP */
					uint8_t pbuf[MAX_WIRE_BUF];
					size_t plen = nonce_bundle_serialize(
						&psig_nb, pbuf, sizeof(pbuf));
					send_factory_msg(cmd, peer_id,
						SS_SUBMSG_PSIG_BUNDLE,
						pbuf, plen);

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: sent PSIG_BUNDLE (%zu bytes)",
						   4 + plen);
				}
			}

			fi->ceremony = CEREMONY_PROPOSED;
			free(pubkeys);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent NONCE_BUNDLE (%zu bytes)",
				   4 + rlen);
		}
		break;

	case SS_SUBMSG_NONCE_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "NONCE_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: deserialize client nonces, set on sessions.
		 * When all clients responded, finalize and send ALL_NONCES. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "NONCE_BUNDLE: fi=%s is_lsp=%d",
			   fi ? "found" : "NULL",
			   fi ? fi->is_lsp : -1);
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad NONCE_BUNDLE");
				break;
			}

			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			secp256k1_context *ctx = global_secp_ctx;

			/* Set client nonces on sessions */
			size_t nonces_set = 0;
			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					cnb.entries[e].pubnonce)) {
					/* Dump first 8 bytes for debug */
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: bad pubnonce entry %zu "
						   "node=%u slot=%u "
						   "bytes=%02x%02x%02x%02x%02x%02x%02x%02x",
						   e, cnb.entries[e].node_idx,
						   cnb.entries[e].signer_slot,
						   cnb.entries[e].pubnonce[0],
						   cnb.entries[e].pubnonce[1],
						   cnb.entries[e].pubnonce[2],
						   cnb.entries[e].pubnonce[3],
						   cnb.entries[e].pubnonce[4],
						   cnb.entries[e].pubnonce[5],
						   cnb.entries[e].pubnonce[6],
						   cnb.entries[e].pubnonce[7]);
					continue;
				}
				if (!factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot,
					&pn)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: set_nonce failed "
						   "node=%u slot=%u",
						   cnb.entries[e].node_idx,
						   cnb.entries[e].signer_slot);
					continue;
				}
				nonces_set++;
			}

			/* Find which client sent this */
			client_state_t *cl = NULL;
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				cl = ss_factory_find_client(fi, pid);
			}
			if (cl) {
				cl->nonce_received = true;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: matched client, nonce_received=true");
			} else {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "LSP: could not match peer to client list");
				/* Force it for single-client demo */
				if (fi->n_clients == 1) {
					fi->clients[0].nonce_received = true;
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: forced nonce_received for solo client");
				}
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: set %zu/%zu client nonces",
				   nonces_set, cnb.n_entries);

			/* Debug: log session state before finalize */
			for (size_t di = 0; di < f->n_nodes; di++) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "Node %zu: n_signers=%zu collected=%d",
					   di, (size_t)f->nodes[di].n_signers,
					   f->nodes[di].signing_session.nonces_collected);
			}

			/* Check if all clients responded */
			if (ss_factory_all_nonces_received(fi)) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: all nonces collected, finalizing");

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: calling factory_sessions_finalize...");

				if (!factory_sessions_finalize(f)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "factory_sessions_finalize failed");
					break;
				}

				fi->ceremony = CEREMONY_NONCES_COLLECTED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: nonces finalized! ceremony=nonces_collected");

				/* Serialize ALL_NONCES: collect all pubnonces
				 * from all signers on all nodes and broadcast
				 * to clients so they can finalize + sign. */
				nonce_bundle_t all_nb;
				memset(&all_nb, 0, sizeof(all_nb));
				memcpy(all_nb.instance_id, fi->instance_id, 32);
				all_nb.n_participants = 1 + fi->n_clients;
				all_nb.n_nodes = f->n_nodes;
				all_nb.n_entries = 0;
				for (uint32_t ni = 0; ni < f->n_nodes; ni++) {
					for (uint32_t si = 0; si < f->nodes[ni].n_signers
					     && all_nb.n_entries < MAX_NONCE_ENTRIES; si++) {
						secp256k1_musig_pubnonce *pn =
							&f->nodes[ni].signing_session.pubnonces[si];
						all_nb.entries[all_nb.n_entries].node_idx = ni;
						all_nb.entries[all_nb.n_entries].signer_slot = si;
						musig_pubnonce_serialize(global_secp_ctx,
							all_nb.entries[all_nb.n_entries].pubnonce,
							pn);
						all_nb.n_entries++;
					}
				}

				uint8_t anbuf[MAX_WIRE_BUF];
				size_t anlen = nonce_bundle_serialize(&all_nb,
					anbuf, sizeof(anbuf));

				for (size_t ci = 0; ci < fi->n_clients; ci++) {
					char nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(nid + j*2, "%02x",
							fi->clients[ci].node_id[j]);
					nid[66] = '\0';
					send_factory_msg(cmd, nid,
						SS_SUBMSG_ALL_NONCES,
						anbuf, anlen);
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: sent ALL_NONCES to %zu clients "
					   "(%zu entries, %zu bytes)",
					   fi->n_clients, all_nb.n_entries, anlen);
			}

			/* ctx is global */
		}
		break;

	case SS_SUBMSG_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ALL_NONCES from %s (len=%zu)",
			   peer_id, len);
		/* Client: LSP sent all aggregated nonces. Set missing nonces
		 * on our sessions, finalize, create partial sigs, respond. */
		if (fi && !fi->is_lsp) {
			nonce_bundle_t anb;
			if (!nonce_bundle_deserialize(&anb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			secp256k1_context *ctx = global_secp_ctx;

			/* Set all nonces from the bundle */
			size_t set_count = 0;
			for (size_t e = 0; e < anb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					anb.entries[e].pubnonce))
					continue;
				factory_session_set_nonce(f,
					anb.entries[e].node_idx,
					anb.entries[e].signer_slot, &pn);
				set_count++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: set %zu/%zu nonces from ALL_NONCES",
				   set_count, anb.n_entries);

			/* Finalize all sessions */
			if (!factory_sessions_finalize(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: finalize after ALL_NONCES failed");
				break;
			}

			fi->ceremony = CEREMONY_NONCES_COLLECTED;

			/* Create partial sigs and send PSIG_BUNDLE */
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id,
				fi->our_participant_idx);
			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec))
				break;

			nonce_bundle_t psig_nb;
			memset(&psig_nb, 0, sizeof(psig_nb));
			memcpy(psig_nb.instance_id, fi->instance_id, 32);
			psig_nb.n_participants = anb.n_participants;
			psig_nb.n_nodes = f->n_nodes;
			psig_nb.n_entries = 0;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&sp->nonces[pi].secnonce;

				int slot = factory_find_signer_slot(
					f, ni, fi->our_participant_idx);
				if (slot < 0) continue;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					ctx, &psig, sn, &kp,
					&f->nodes[ni].signing_session))
					continue;

				musig_partial_sig_serialize(ctx,
					psig_nb.entries[psig_nb.n_entries].pubnonce,
					&psig);
				psig_nb.entries[psig_nb.n_entries].node_idx = ni;
				psig_nb.entries[psig_nb.n_entries].signer_slot = slot;
				psig_nb.n_entries++;
			}

			uint8_t pbuf[MAX_WIRE_BUF];
			size_t plen = nonce_bundle_serialize(
				&psig_nb, pbuf, sizeof(pbuf));
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_PSIG_BUNDLE, pbuf, plen);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent PSIG_BUNDLE from ALL_NONCES "
				   "(%zu partial sigs, %zu bytes)",
				   psig_nb.n_entries, plen);
		}
		break;

	case SS_SUBMSG_PSIG_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "PSIG_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad PSIG_BUNDLE");
				break;
			}

			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			/* Set client partial sigs */
			size_t psigs_set = 0;
			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: bad psig entry %zu", e);
					continue;
				}
				if (!factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot,
					&ps)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: set_partial_sig failed %zu", e);
					continue;
				}
				psigs_set++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: set %zu/%zu client partial sigs",
				   psigs_set, pnb.n_entries);

			/* Create LSP's own partial sigs using stored secnonces */
			{
				secp256k1_keypair lsp_kp;
				if (!secp256k1_keypair_create(global_secp_ctx,
					&lsp_kp, fi->our_seckey)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: keypair create failed");
					break;
				}

				musig_nonce_pool_t *lsp_pool =
					(musig_nonce_pool_t *)fi->nonce_pool;
				size_t lsp_psigs = 0;
				for (size_t si = 0; si < fi->n_secnonces; si++) {
					uint32_t pi = fi->secnonce_pool_idx[si];
					uint32_t ni = fi->secnonce_node_idx[si];
					secp256k1_musig_secnonce *sn =
						&lsp_pool->nonces[pi].secnonce;

					secp256k1_musig_partial_sig psig;
					if (!musig_create_partial_sig(
						global_secp_ctx, &psig, sn,
						&lsp_kp,
						&f->nodes[ni].signing_session)) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "LSP: partial_sig failed node %u", ni);
						continue;
					}

					int slot = factory_find_signer_slot(
						f, ni, fi->our_participant_idx);
					if (slot < 0) continue;

					if (!factory_session_set_partial_sig(
						f, ni, (size_t)slot, &psig)) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "LSP: set own psig failed node %u", ni);
						continue;
					}
					lsp_psigs++;
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: created %zu own partial sigs",
					   lsp_psigs);
			}

			/* Try to complete — all sigs should be set now */
			if (!factory_sessions_complete(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: factory_sessions_complete failed");
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: FACTORY TREE SIGNED!");

				/* Build distribution TX (nLockTime fallback).
				 * This TX lets clients recover funds if LSP
				 * vanishes — the core SuperScalar safety net. */
				tx_output_t dist_out[MAX_DIST_OUTPUTS];
				size_t n_dist = factory_compute_distribution_outputs(
					f, dist_out, MAX_DIST_OUTPUTS, 500);

				if (n_dist > 0 && factory_build_distribution_tx_unsigned(
					f, dist_out, n_dist,
					ss_state.current_blockheight + DW_STEP_BLOCKS * DIST_TX_LOCKTIME_DAYS)) {
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: distribution TX built "
						   "(%zu outputs, sighash ready)",
						   n_dist);

					/* Generate nonce for dist TX signing.
					 * Virtual node idx = f->n_nodes. */
					uint32_t dist_node_idx = f->n_nodes;
					secp256k1_context *dctx = global_secp_ctx;
					unsigned char lsp_sk[32];
					derive_factory_seckey(lsp_sk, fi->instance_id, 0);
					secp256k1_pubkey lsp_pk;
					if (!secp256k1_ec_pubkey_create(dctx, &lsp_pk, lsp_sk))
						break;

					musig_nonce_pool_t *dpool = calloc(1,
						sizeof(musig_nonce_pool_t));
					musig_nonce_pool_generate(dctx, dpool, 1,
						lsp_sk, &lsp_pk, NULL);

					secp256k1_musig_secnonce *dsec;
					secp256k1_musig_pubnonce dpub;
					musig_nonce_pool_next(dpool, &dsec, &dpub);

					/* Init MuSig2 signing session for dist TX
					 * virtual node and set LSP's own nonce */
					factory_session_init_node(f, dist_node_idx);
					factory_session_set_nonce(f, dist_node_idx,
						0, &dpub);

					/* Build DIST_PROPOSE payload:
					 * instance_id(32) + dist_tx_hex_len(4)
					 * + dist_tx_hex(var) + nonce(66) */
					uint8_t dpayload[MAX_WIRE_BUF];
					uint8_t *dp = dpayload;
					memcpy(dp, fi->instance_id, 32); dp += 32;
					/* TX length */
					uint32_t txlen = f->dist_unsigned_tx.len;
					dp[0] = (txlen >> 24) & 0xFF;
					dp[1] = (txlen >> 16) & 0xFF;
					dp[2] = (txlen >> 8) & 0xFF;
					dp[3] = txlen & 0xFF;
					dp += 4;
					/* TX data */
					memcpy(dp, f->dist_unsigned_tx.data, txlen);
					dp += txlen;
					/* LSP nonce */
					musig_pubnonce_serialize(dctx, dp, &dpub);
					dp += 66;

					size_t dplen = (size_t)(dp - dpayload);

					/* Store dist nonce pool for later signing */
					/* Reuse nonce_pool — tree signing is done */
					if (fi->nonce_pool) free(fi->nonce_pool);
					fi->nonce_pool = dpool;
					fi->n_secnonces = 1;
					fi->secnonce_pool_idx[0] = 0;
					fi->secnonce_node_idx[0] = f->n_nodes;

					/* Send DIST_PROPOSE to all clients */
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_DIST_PROPOSE,
							dpayload, dplen);
					}

					/* Reset ceremony tracking for dist round */
					ss_factory_reset_ceremony(fi);
					fi->ceremony = CEREMONY_PSIGS_COLLECTED;

					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent DIST_PROPOSE to %zu "
						   "clients (%zu bytes)",
						   fi->n_clients, dplen);
				} else {
					/* Distribution TX build failed — proceed
					 * without it (degraded safety) */
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "LSP: distribution TX build "
						   "failed, proceeding without");
					fi->ceremony = CEREMONY_COMPLETE;
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_FACTORY_READY,
							fi->instance_id, 32);
					}
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent FACTORY_READY (no dist TX)");
					ss_save_factory(cmd, fi);
				}
			}
		}
		break;

	case SS_SUBMSG_FACTORY_READY:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_READY from %s (len=%zu)",
			   peer_id, len);
		/* Client side: factory tree is fully signed.
		 * The LSP will call fundchannel_start which sends us an
		 * open_channel with channel_in_factory TLV.
		 * Our openchannel hook (handle_openchannel) maps it. */
		if (fi) {
			fi->ceremony = CEREMONY_COMPLETE;
			ss_save_factory(cmd, fi);
		}
		break;

	case SS_SUBMSG_DIST_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client: LSP sent unsigned distribution TX + nonce.
		 * Parse TX, generate nonce, create partial sig, respond. */
		if (fi && len > 36) {
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			secp256k1_context *ctx = global_secp_ctx;
			const uint8_t *dp = data + 32; /* skip instance_id */
			size_t rem = len - 32;

			/* Parse TX length + data */
			if (rem < 4) break;
			uint32_t txlen = ((uint32_t)dp[0] << 24) |
				((uint32_t)dp[1] << 16) |
				((uint32_t)dp[2] << 8) | dp[3];
			dp += 4; rem -= 4;
			if (rem < txlen + 66) break;

			/* Store unsigned dist TX in factory */
			tx_buf_init(&f->dist_unsigned_tx, txlen);
			memcpy(f->dist_unsigned_tx.data, dp, txlen);
			f->dist_unsigned_tx.len = txlen;
			f->dist_tx_ready = 1;
			dp += txlen; rem -= txlen;

			/* Parse LSP nonce */
			secp256k1_musig_pubnonce lsp_nonce;
			musig_pubnonce_parse(ctx, &lsp_nonce, dp);

			/* Generate our nonce for dist TX */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);
			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

			if (fi->nonce_pool) free(fi->nonce_pool);
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool, 1,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			fi->n_secnonces = 0;

			secp256k1_musig_secnonce *sec;
			secp256k1_musig_pubnonce pub;
			musig_nonce_pool_next(pool, &sec, &pub);
			fi->secnonce_pool_idx[0] = 0;
			fi->secnonce_node_idx[0] = f->n_nodes;
			fi->n_secnonces = 1;

			/* Init signing session for dist TX (virtual node) */
			uint32_t dist_idx = f->n_nodes;
			factory_session_init_node(f, dist_idx);
			factory_session_set_nonce(f, dist_idx, 0, &lsp_nonce);
			factory_session_set_nonce(f, dist_idx, our_idx, &pub);

			/* Send DIST_NONCE */
			nonce_bundle_t nresp;
			memset(&nresp, 0, sizeof(nresp));
			memcpy(nresp.instance_id, fi->instance_id, 32);
			nresp.n_participants = 1 + fi->n_clients;
			nresp.n_nodes = 1;
			nresp.n_entries = 1;
			nresp.entries[0].node_idx = dist_idx;
			nresp.entries[0].signer_slot = our_idx;
			musig_pubnonce_serialize(ctx,
				nresp.entries[0].pubnonce, &pub);

			uint8_t nbuf[MAX_WIRE_BUF];
			size_t nlen = nonce_bundle_serialize(&nresp,
				nbuf, sizeof(nbuf));
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_DIST_NONCE, nbuf, nlen);

			/* Finalize and create partial sig */
			if (factory_session_finalize_node(f, dist_idx)) {
				secp256k1_keypair kp;
				if (!secp256k1_keypair_create(ctx, &kp, our_sec))
					break;
				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(ctx, &psig, sec,
					&kp, &f->nodes[dist_idx].signing_session)) {

					nonce_bundle_t presp;
					memset(&presp, 0, sizeof(presp));
					memcpy(presp.instance_id, fi->instance_id, 32);
					presp.n_participants = nresp.n_participants;
					presp.n_nodes = 1;
					presp.n_entries = 1;
					presp.entries[0].node_idx = dist_idx;
					presp.entries[0].signer_slot = our_idx;
					musig_partial_sig_serialize(ctx,
						presp.entries[0].pubnonce, &psig);

					uint8_t pbuf[MAX_WIRE_BUF];
					size_t plen = nonce_bundle_serialize(
						&presp, pbuf, sizeof(pbuf));
					send_factory_msg(cmd, peer_id,
						SS_SUBMSG_DIST_PSIG, pbuf, plen);

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: sent DIST_NONCE + DIST_PSIG");
				}
			}
		}
		break;

	case SS_SUBMSG_DIST_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_NONCE from %s (len=%zu)", peer_id, len);
		/* LSP: client sent dist nonce — set on session */
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(global_secp_ctx, &pn,
					cnb.entries[e].pubnonce);
				factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot, &pn);
			}
			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: dist nonces set");

			/* Finalize dist signing session */
			uint32_t dist_idx = f->n_nodes;
			if (!factory_session_finalize_node(f, dist_idx))
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: dist finalize failed");
		}
		break;

	case SS_SUBMSG_DIST_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_PSIG from %s (len=%zu)", peer_id, len);
		/* LSP: client sent dist partial sig — complete and send FACTORY_READY */
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			/* Set client psig */
			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce);
				factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot, &ps);
			}

			/* Create LSP's own dist psig */
			uint32_t dist_idx = f->n_nodes;
			musig_nonce_pool_t *dpool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			if (dpool && fi->n_secnonces > 0) {
				secp256k1_keypair lsp_kp;
				if (!secp256k1_keypair_create(global_secp_ctx,
					&lsp_kp, fi->our_seckey))
					break;
				secp256k1_musig_secnonce *sn =
					&dpool->nonces[0].secnonce;
				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(global_secp_ctx,
					&psig, sn, &lsp_kp,
					&f->nodes[dist_idx].signing_session)) {
					int slot = factory_find_signer_slot(
						f, dist_idx, 0);
					if (slot >= 0)
						factory_session_set_partial_sig(
							f, dist_idx, (size_t)slot,
							&psig);
				}
			}

			/* Complete dist signing */
			if (factory_session_complete_node(f, dist_idx)) {
				f->dist_tx_ready = 2; /* signed */
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: DISTRIBUTION TX SIGNED!");

				if (fi->rotation_in_progress) {
					/* Rotation dist TX done — finish rotation */
					rotate_finish_and_notify(cmd, fi);
				} else {
					/* Creation dist TX done — send FACTORY_READY */
					fi->ceremony = CEREMONY_COMPLETE;
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_FACTORY_READY,
							fi->instance_id, 32);
					}
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent FACTORY_READY to %zu "
						   "clients (with signed dist TX)"
						   " — call factory-open-channels",
						   fi->n_clients);
					ss_save_factory(cmd, fi);
				}
			} else {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: dist session_complete failed");
				if (fi->rotation_in_progress) {
					rotate_finish_and_notify(cmd, fi);
				} else {
					fi->ceremony = CEREMONY_COMPLETE;
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_FACTORY_READY,
							fi->instance_id, 32);
					}
				}
			}
		}
		break;

	case SS_SUBMSG_ROTATE_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP wants to advance DW epoch.
		 * Payload: old_epoch(4) + new_epoch(4) + nonce_bundle */
		if (len < 8) break;
		{
			uint32_t old_epoch = ((uint32_t)data[0] << 24) |
				((uint32_t)data[1] << 16) |
				((uint32_t)data[2] << 8) | data[3];
			uint32_t new_epoch = ((uint32_t)data[4] << 24) |
				((uint32_t)data[5] << 16) |
				((uint32_t)data[6] << 8) | data[7];

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: rotation epoch %u → %u",
				   old_epoch, new_epoch);

			nonce_bundle_t nb;
			if (!nonce_bundle_deserialize(&nb, data + 8, len - 8)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad ROTATE_PROPOSE nonce bundle");
				break;
			}

			if (!fi) {
				fi = ss_factory_find(&ss_state, nb.instance_id);
			}
			if (!fi || !fi->lib_factory) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "No factory for rotation");
				break;
			}

			factory_t *factory = (factory_t *)fi->lib_factory;
			secp256k1_context *ctx = global_secp_ctx;

			/* Advance our DW counter to match */
			dw_counter_advance(&factory->counter);
			fi->epoch = new_epoch;

			/* Rebuild node transactions */
			for (size_t ni = 0; ni < factory->n_nodes; ni++)
				factory_rebuild_node_tx(factory, ni);

			/* Re-init signing sessions */
			factory_sessions_init(factory);

			/* Set LSP nonces on sessions */
			for (size_t e = 0; e < nb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					nb.entries[e].pubnonce);
				factory_session_set_nonce(factory,
					nb.entries[e].node_idx,
					nb.entries[e].signer_slot, &pn);
			}

			/* Generate our nonces */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);

			size_t our_count = factory_count_nodes_for_participant(
				factory, our_idx);

			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

			if (fi->nonce_pool) {
				free(fi->nonce_pool);
				fi->nonce_pool = NULL;
			}
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool, our_count,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			memcpy(fi->our_seckey, our_sec, 32);
			fi->n_secnonces = 0;

			nonce_bundle_t resp;
			memset(&resp, 0, sizeof(resp));
			memcpy(resp.instance_id, fi->instance_id, 32);
			resp.n_participants = nb.n_participants;
			resp.n_nodes = factory->n_nodes;
			resp.n_entries = 0;

			size_t pool_entry = 0;
			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *sec;
				secp256k1_musig_pubnonce pub;
				if (!musig_nonce_pool_next(pool, &sec, &pub))
					break;

				fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
				fi->secnonce_node_idx[fi->n_secnonces] = ni;
				fi->n_secnonces++;
				pool_entry++;

				factory_session_set_nonce(factory, ni,
					(size_t)slot, &pub);
				musig_pubnonce_serialize(ctx,
					resp.entries[resp.n_entries].pubnonce,
					&pub);
				resp.entries[resp.n_entries].node_idx = ni;
				resp.entries[resp.n_entries].signer_slot = slot;
				resp.n_entries++;
			}

			/* Send ROTATE_NONCE */
			uint8_t rbuf[MAX_WIRE_BUF];
			size_t rlen = nonce_bundle_serialize(&resp,
				rbuf, sizeof(rbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_NONCE,
					 rbuf, rlen);

			/* Finalize and create partial sigs */
			if (!factory_sessions_finalize(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate finalize failed");
				break;
			}

			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate keypair failed");
				break;
			}

			nonce_bundle_t psig_nb;
			memset(&psig_nb, 0, sizeof(psig_nb));
			memcpy(psig_nb.instance_id, fi->instance_id, 32);
			psig_nb.n_participants = nb.n_participants;
			psig_nb.n_nodes = factory->n_nodes;
			psig_nb.n_entries = 0;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&sp->nonces[pi].secnonce;

				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					ctx, &psig, sn, &kp,
					&factory->nodes[ni].signing_session)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Client: rotate psig failed node %u", ni);
					continue;
				}

				musig_partial_sig_serialize(ctx,
					psig_nb.entries[psig_nb.n_entries].pubnonce,
					&psig);
				psig_nb.entries[psig_nb.n_entries].node_idx = ni;
				psig_nb.entries[psig_nb.n_entries].signer_slot = slot;
				psig_nb.n_entries++;
			}

			/* Send ROTATE_PSIG */
			uint8_t pbuf[MAX_WIRE_BUF];
			size_t plen = nonce_bundle_serialize(&psig_nb,
				pbuf, sizeof(pbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_PSIG,
					 pbuf, plen);

			fi->ceremony = CEREMONY_ROTATING;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent ROTATE_NONCE + ROTATE_PSIG "
				   "(%zu psigs)", psig_nb.n_entries);
		}
		break;

	case SS_SUBMSG_ROTATE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_NONCE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation nonces */
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			secp256k1_context *ctx = global_secp_ctx;

			size_t nonces_set = 0;
			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					cnb.entries[e].pubnonce))
					continue;
				if (!factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot, &pn))
					continue;
				nonces_set++;
			}

			/* Mark client nonce received */
			if (fi->n_clients == 1)
				fi->clients[0].nonce_received = true;

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate nonces set %zu/%zu",
				   nonces_set, cnb.n_entries);

			if (ss_factory_all_nonces_received(fi)) {
				if (!factory_sessions_finalize(f)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: rotate finalize failed");
				} else {
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: rotate nonces finalized");
				}
			}
		}
		break;

	case SS_SUBMSG_ROTATE_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_PSIG from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation partial sigs */
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			/* Set client psigs */
			size_t psigs_set = 0;
			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce))
					continue;
				if (!factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot, &ps))
					continue;
				psigs_set++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate client psigs set %zu/%zu",
				   psigs_set, pnb.n_entries);

			/* Create LSP's own psigs */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: rotate keypair failed");
				break;
			}

			musig_nonce_pool_t *lsp_pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			size_t lsp_psigs = 0;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&lsp_pool->nonces[pi].secnonce;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					global_secp_ctx, &psig, sn, &lsp_kp,
					&f->nodes[ni].signing_session))
					continue;

				int slot = factory_find_signer_slot(
					f, ni, fi->our_participant_idx);
				if (slot < 0) continue;

				factory_session_set_partial_sig(
					f, ni, (size_t)slot, &psig);
				lsp_psigs++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: created %zu own rotate psigs",
				   lsp_psigs);

			/* Try to complete */
			if (!factory_sessions_complete(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: rotate sessions_complete failed");
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: ROTATION TREE SIGNED! epoch=%u",
					   fi->epoch);

				/* Build new distribution TX for rotated tree */
				fi->rotation_in_progress = true;
				tx_output_t rot_dist_out[MAX_DIST_OUTPUTS];
				size_t n_rdist = factory_compute_distribution_outputs(
					f, rot_dist_out, MAX_DIST_OUTPUTS, 500);

				if (n_rdist > 0 && factory_build_distribution_tx_unsigned(
					f, rot_dist_out, n_rdist,
					ss_state.current_blockheight + DW_STEP_BLOCKS * DIST_TX_LOCKTIME_DAYS)) {
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: rotate dist TX built "
						   "(%zu outputs)", n_rdist);

					/* Generate nonce for dist TX */
					uint32_t rdist_idx = f->n_nodes;
					secp256k1_context *rdctx = global_secp_ctx;
					unsigned char rlsp_sk[32];
					derive_factory_seckey(rlsp_sk, fi->instance_id, 0);
					secp256k1_pubkey rlsp_pk;
					if (!secp256k1_ec_pubkey_create(rdctx,
						&rlsp_pk, rlsp_sk))
						break;

					musig_nonce_pool_t *rdpool = calloc(1,
						sizeof(musig_nonce_pool_t));
					musig_nonce_pool_generate(rdctx, rdpool, 1,
						rlsp_sk, &rlsp_pk, NULL);

					secp256k1_musig_secnonce *rdsec;
					secp256k1_musig_pubnonce rdpub;
					musig_nonce_pool_next(rdpool, &rdsec, &rdpub);

					/* Init session for dist TX virtual node */
					factory_session_init_node(f, rdist_idx);
					factory_session_set_nonce(f, rdist_idx,
						0, &rdpub);

					/* Build DIST_PROPOSE payload */
					uint8_t rdpayload[MAX_WIRE_BUF];
					uint8_t *rdp = rdpayload;
					memcpy(rdp, fi->instance_id, 32); rdp += 32;
					uint32_t rtxlen = f->dist_unsigned_tx.len;
					rdp[0] = (rtxlen >> 24) & 0xFF;
					rdp[1] = (rtxlen >> 16) & 0xFF;
					rdp[2] = (rtxlen >> 8) & 0xFF;
					rdp[3] = rtxlen & 0xFF;
					rdp += 4;
					memcpy(rdp, f->dist_unsigned_tx.data, rtxlen);
					rdp += rtxlen;
					musig_pubnonce_serialize(rdctx,
						rdp, &rdpub);
					rdp += 66;
					size_t rdplen = (size_t)(rdp - rdpayload);

					/* Store nonce pool for dist signing */
					if (fi->nonce_pool) free(fi->nonce_pool);
					fi->nonce_pool = rdpool;
					fi->n_secnonces = 1;
					fi->secnonce_pool_idx[0] = 0;
					fi->secnonce_node_idx[0] = f->n_nodes;

					/* Send DIST_PROPOSE to clients */
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_DIST_PROPOSE,
							rdpayload, rdplen);
					}

					ss_factory_reset_ceremony(fi);
					fi->ceremony = CEREMONY_PSIGS_COLLECTED;
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent rotate DIST_PROPOSE "
						   "to %zu clients (%zu bytes)",
						   fi->n_clients, rdplen);
				} else {
					/* Dist TX failed — proceed without */
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "LSP: rotate dist TX failed, "
						   "completing without");
					rotate_finish_and_notify(cmd, fi);
				}
			}
		}
		break;

	case SS_SUBMSG_ROTATE_COMPLETE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_COMPLETE from %s (len=%zu)",
			   peer_id, len);
		if (fi) {
			fi->ceremony = CEREMONY_ROTATE_COMPLETE;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: rotation complete, epoch=%u",
				   fi->epoch);
		}
		break;

	case SS_SUBMSG_REVOKE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "REVOKE from %s (len=%zu)", peer_id, len);
		/* Client: store revocation secret for breach detection.
		 * fi is NULL here (payload starts with epoch, not instance_id).
		 * Find factory by scanning for one with this peer as LSP. */
		if (!fi) {
			for (size_t i = 0; i < ss_state.n_factories; i++) {
				if (!ss_state.factories[i]->is_lsp) {
					fi = ss_state.factories[i];
					break;
				}
			}
		}
		if (fi && len >= 36) {
			uint32_t rev_epoch = ((uint32_t)data[0] << 24) |
				((uint32_t)data[1] << 16) |
				((uint32_t)data[2] << 8) | data[3];
			const uint8_t *rev_secret = data + 4;

			ss_factory_add_breach_data(fi, rev_epoch,
						   rev_secret, NULL, 0);

			fi->ceremony = CEREMONY_REVOKED;
			ss_save_factory(cmd, fi);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: stored revocation for epoch %u, "
				   "n_breach=%zu",
				   rev_epoch, fi->n_breach_epochs);
		}
		break;

	case SS_SUBMSG_CLOSE_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* fi is NULL (payload starts with output count, not instance_id) */
		if (!fi) {
			for (size_t i = 0; i < ss_state.n_factories; i++) {
				if (!ss_state.factories[i]->is_lsp) {
					fi = ss_state.factories[i];
					break;
				}
			}
		}
		if (fi && len >= 4) {
			factory_t *factory = (factory_t *)fi->lib_factory;
			if (!factory) break;
			secp256k1_context *ctx = global_secp_ctx;

			/* Parse output distribution */
			const uint8_t *p = data;
			uint32_t n_outputs = ((uint32_t)p[0] << 24) |
				((uint32_t)p[1] << 16) |
				((uint32_t)p[2] << 8) | p[3];
			p += 4;

			if (n_outputs > 8) break;
			tx_output_t outputs[8];
			for (uint32_t oi = 0; oi < n_outputs; oi++) {
				if (p + 10 > data + len) break;
				outputs[oi].amount_sats =
					((uint64_t)p[0] << 56) |
					((uint64_t)p[1] << 48) |
					((uint64_t)p[2] << 40) |
					((uint64_t)p[3] << 32) |
					((uint64_t)p[4] << 24) |
					((uint64_t)p[5] << 16) |
					((uint64_t)p[6] << 8) | p[7];
				p += 8;
				uint16_t spk_len = ((uint16_t)p[0] << 8) | p[1];
				p += 2;
				if (spk_len > 34 || p + spk_len > data + len) break;
				memcpy(outputs[oi].script_pubkey, p, spk_len);
				outputs[oi].script_pubkey_len = spk_len;
				p += spk_len;
			}

			/* Build unsigned close tx to get sighash */
			tx_buf_t close_tx;
			unsigned char sighash[32];
			tx_buf_init(&close_tx, 512);

			if (!factory_build_cooperative_close_unsigned(
				factory, &close_tx, sighash,
				outputs, n_outputs,
				ss_state.current_blockheight)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: close tx build failed");
				tx_buf_free(&close_tx);
				break;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: close tx built (%zu bytes)",
				   close_tx.len);

			/* Parse LSP nonces from remainder */
			size_t hdr_consumed = (size_t)(p - data);
			nonce_bundle_t cnb;
			if (hdr_consumed < len &&
			    nonce_bundle_deserialize(&cnb,
				p, len - hdr_consumed)) {
				/* Re-init just node 0 session for close signing */
				factory_session_init_node(factory, 0);

				for (size_t e = 0; e < cnb.n_entries; e++) {
					secp256k1_musig_pubnonce pn;
					musig_pubnonce_parse(ctx, &pn,
						cnb.entries[e].pubnonce);
					factory_session_set_nonce(factory,
						cnb.entries[e].node_idx,
						cnb.entries[e].signer_slot,
						&pn);
				}
			}

			/* Generate our nonces */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);

			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

			if (fi->nonce_pool) free(fi->nonce_pool);
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			/* Close uses 1 signing session (kickoff root) */
			musig_nonce_pool_generate(ctx, pool, 1,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			fi->n_secnonces = 0;

			secp256k1_musig_secnonce *sec;
			secp256k1_musig_pubnonce pub;
			musig_nonce_pool_next(pool, &sec, &pub);
			fi->secnonce_pool_idx[0] = 0;
			fi->secnonce_node_idx[0] = 0;
			fi->n_secnonces = 1;
			factory_session_set_nonce(factory, 0, our_idx, &pub);

			/* Send CLOSE_NONCE */
			nonce_bundle_t nresp;
			memset(&nresp, 0, sizeof(nresp));
			memcpy(nresp.instance_id, fi->instance_id, 32);
			nresp.n_participants = 2;
			nresp.n_nodes = 1;
			nresp.n_entries = 1;
			nresp.entries[0].node_idx = 0;
			nresp.entries[0].signer_slot = our_idx;
			musig_pubnonce_serialize(ctx,
				nresp.entries[0].pubnonce, &pub);

			uint8_t nbuf[MAX_WIRE_BUF];
			size_t nlen = nonce_bundle_serialize(&nresp,
				nbuf, sizeof(nbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_CLOSE_NONCE,
					 nbuf, nlen);

			/* Finalize node 0 and create partial sig */
			factory_session_finalize_node(factory, 0);

			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec))
				break;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			secp256k1_musig_secnonce *sn =
				&sp->nonces[0].secnonce;

			secp256k1_musig_partial_sig psig;
			if (musig_create_partial_sig(ctx, &psig, sn, &kp,
				&factory->nodes[0].signing_session)) {

				nonce_bundle_t presp;
				memset(&presp, 0, sizeof(presp));
				memcpy(presp.instance_id, fi->instance_id, 32);
				presp.n_participants = 2;
				presp.n_nodes = 1;
				presp.n_entries = 1;
				presp.entries[0].node_idx = 0;
				presp.entries[0].signer_slot = our_idx;
				musig_partial_sig_serialize(ctx,
					presp.entries[0].pubnonce, &psig);

				uint8_t pbuf[MAX_WIRE_BUF];
				size_t plen = nonce_bundle_serialize(&presp,
					pbuf, sizeof(pbuf));
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_CLOSE_PSIG,
					pbuf, plen);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: sent CLOSE_NONCE + CLOSE_PSIG");
			}

			tx_buf_free(&close_tx);
			fi->lifecycle = FACTORY_LIFECYCLE_DYING;
		}
		break;

	case SS_SUBMSG_CLOSE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_NONCE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent close nonces */
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(global_secp_ctx, &pn,
					cnb.entries[e].pubnonce))
					continue;
				factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot, &pn);
			}

			/* Finalize just node 0 (close tx) */
			if (!factory_session_finalize_node(f, 0))
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: close finalize failed");
			else
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: close nonces finalized");
		}
		break;

	case SS_SUBMSG_CLOSE_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_ALL_NONCES from %s", peer_id);
		break;

	case SS_SUBMSG_CLOSE_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_PSIG from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent close partial sig */
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce))
					continue;
				factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot, &ps);
			}

			/* Create LSP's own partial sig */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey))
				break;

			musig_nonce_pool_t *lsp_pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			if (lsp_pool && fi->n_secnonces > 0) {
				uint32_t pi = fi->secnonce_pool_idx[0];
				secp256k1_musig_secnonce *sn =
					&lsp_pool->nonces[pi].secnonce;

				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(
					global_secp_ctx, &psig, sn, &lsp_kp,
					&f->nodes[0].signing_session)) {
					factory_session_set_partial_sig(
						f, 0, fi->our_participant_idx,
						&psig);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: created own close psig");
				}
			}

			/* Try to complete just node 0 (close tx) */
			if (factory_session_complete_node(f, 0)) {
				fi->lifecycle = FACTORY_LIFECYCLE_EXPIRED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: COOPERATIVE CLOSE SIGNED!");

				/* Broadcast the close TX (node 0) */
				tx_buf_t *ctx_buf = &f->nodes[0].signed_tx;
				if (ctx_buf->data && ctx_buf->len > 0) {
					char *ctx_hex = tal_arr(cmd, char,
						ctx_buf->len * 2 + 1);
					for (size_t h = 0; h < ctx_buf->len; h++)
						sprintf(ctx_hex + h*2, "%02x",
							ctx_buf->data[h]);
					struct out_req *btx = jsonrpc_request_start(
						cmd, "sendrawtransaction",
						rpc_done, rpc_err, fi);
					json_add_string(btx->js, "tx", ctx_hex);
					send_outreq(btx);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: broadcast cooperative close TX");
				}

				/* Send CLOSE_DONE */
				for (size_t ci = 0; ci < fi->n_clients; ci++) {
					char nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(nid + j*2, "%02x",
							fi->clients[ci].node_id[j]);
					nid[66] = '\0';
					send_factory_msg(cmd, nid,
						SS_SUBMSG_CLOSE_DONE,
						fi->instance_id, 32);
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: sent CLOSE_DONE to %zu clients",
					   fi->n_clients);
				ss_save_factory(cmd, fi);

				/* Close open channels in this factory */
				for (size_t ch = 0; ch < fi->n_channels; ch++) {
					char cid_hex[65];
					for (int j = 0; j < 32; j++)
						sprintf(cid_hex + j*2, "%02x",
							fi->channels[ch].channel_id[j]);
					struct out_req *creq = jsonrpc_request_start(
						cmd, "close",
						rpc_done, rpc_err, fi);
					json_add_string(creq->js, "id", cid_hex);
					send_outreq(creq);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: closing channel %zu", ch);
				}
			} else {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: close sessions_complete failed");
			}
		}
		break;

	case SS_SUBMSG_CLOSE_DONE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_DONE from %s (len=%zu)",
			   peer_id, len);
		if (fi) {
			fi->lifecycle = FACTORY_LIFECYCLE_EXPIRED;
			ss_save_factory(cmd, fi);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: factory closed cooperatively");

			/* Close our side of each channel in this factory */
			for (size_t ch = 0; ch < fi->n_channels; ch++) {
				char cid_hex[65];
				for (int j = 0; j < 32; j++)
					sprintf(cid_hex + j*2, "%02x",
						fi->channels[ch].channel_id[j]);
				struct out_req *creq = jsonrpc_request_start(
					cmd, "close",
					rpc_done, rpc_err, fi);
				json_add_string(creq->js, "id", cid_hex);
				send_outreq(creq);
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: closing channel %zu", ch);
			}
		}
		break;

	default:
		plugin_log(plugin_handle, LOG_DBG,
			   "Unknown submsg 0x%04x from %s (len=%zu)",
			   submsg_id, peer_id, len);
		break;
	}
}

/* Dispatch bLIP-56 factory change submessages */
static void dispatch_blip56_submsg(struct command *cmd,
				   const char *peer_id,
				   u16 submsg_id,
				   const u8 *data, size_t len)
{
	switch (submsg_id) {
	case BLIP56_SUBMSG_SUPPORTED_PROTOCOLS: /* 2 */
		/* Peer sent their supported factory protocol IDs.
		 * TLV type 512: concatenated 32-byte IDs. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "supported_factory_protocols from %s (len=%zu)",
			   peer_id, len);
		if (len >= 35) {
			/* Parse TLV: skip type(3)+len(1), read IDs */
			const uint8_t *ids = data + 4;
			size_t ids_len = len - 4;
			size_t n_protos = ids_len / 32;
			bool has_superscalar = false;
			for (size_t pi = 0; pi < n_protos; pi++) {
				if (memcmp(ids + pi * 32,
					   SUPERSCALAR_PROTOCOL_ID, 32) == 0) {
					has_superscalar = true;
					break;
				}
			}
			plugin_log(plugin_handle, LOG_INFORM,
				   "Peer %s supports %zu protocols, "
				   "SuperScalar=%s",
				   peer_id, n_protos,
				   has_superscalar ? "yes" : "no");
		}
		break;

	case BLIP56_SUBMSG_FACTORY_PIGGYBACK: /* 4 */
		/* Unwrap factory_piggyback: extract protocol_id + payload.
		 * TLV[0]=protocol_id(32), TLV[1024]=payload(ss_submsg+data) */
		if (len >= 36) {
			/* Skip TLV type 0 header (type=1byte, len=1byte) */
			const uint8_t *proto_id = data + 2;
			if (memcmp(proto_id, SUPERSCALAR_PROTOCOL_ID, 32) != 0) {
				plugin_log(plugin_handle, LOG_DBG,
					   "Unknown factory protocol in piggyback");
				break;
			}
			/* Find TLV type 1024 payload */
			const uint8_t *p = data + 34;
			size_t remaining = len - 34;
			if (remaining < 4) break;
			/* Skip TLV type 1024 header (fd 04 00 + len) */
			p += 3; remaining -= 3;
			size_t payload_len;
			if (*p < 253) {
				payload_len = *p++;
				remaining--;
			} else {
				payload_len = (p[1] << 8) | p[2];
				p += 3; remaining -= 3;
			}
			if (remaining < 2 || payload_len < 2) break;
			uint16_t ss_sub = (p[0] << 8) | p[1];
			dispatch_superscalar_submsg(cmd, peer_id,
				ss_sub, p + 2, payload_len - 2);
		}
		break;

	case 6: /* factory_change_init */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_init from %s (len=%zu)",
			   peer_id, len);
		/* Extract channel_id + funding_contribution + funding_pubkey
		 * from TLV type 1536. Validate with our factory state.
		 * For now, auto-ack to proceed with the change. */
		{
			/* Send factory_change_ack (submsg 8) with same TLVs */
			uint8_t ack_wire[4 + 256];
			ack_wire[0] = 0x80; ack_wire[1] = 0x20;
			ack_wire[2] = 0x00; ack_wire[3] = 0x08;
			memcpy(ack_wire + 4, data, len < 256 ? len : 256);
			size_t ack_len = 4 + (len < 256 ? len : 256);

			char *ahex = tal_arr(cmd, char, ack_len * 2 + 1);
			for (size_t h = 0; h < ack_len; h++)
				sprintf(ahex + h*2, "%02x", ack_wire[h]);

			struct out_req *areq = jsonrpc_request_start(cmd,
				"sendcustommsg", rpc_done, rpc_err, cmd);
			json_add_string(areq->js, "node_id", peer_id);
			json_add_string(areq->js, "msg", ahex);
			send_outreq(areq);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Sent factory_change_ack to %s", peer_id);
		}
		break;

	case 8: /* factory_change_ack */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_ack from %s (len=%zu)",
			   peer_id, len);
		/* Peer acknowledged our factory_change_init.
		 * Next: send factory_change_funding (submsg 10) with new txid. */
		break;

	case 10: /* factory_change_funding */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_funding from %s (len=%zu)",
			   peer_id, len);
		/* Peer sent new funding txid. Validate against our factory state.
		 * Next: sign commitment for new funding outpoint. */
		break;

	case 12: /* factory_change_continue */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_continue from %s", peer_id);
		/* Peer says new factory state is valid. Resume channel. */
		break;

	case 14: /* factory_change_locked */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_locked from %s", peer_id);
		/* Old state invalidated. New state is the sole valid state. */
		break;

	default:
		/* Direct SuperScalar submessages (0x0100+) for backward compat */
		if (submsg_id >= 0x0100 && submsg_id <= 0x01FF) {
			dispatch_superscalar_submsg(cmd, peer_id,
						    submsg_id, data, len);
		} else {
			plugin_log(plugin_handle, LOG_DBG,
				   "Unknown submsg %u from %s", submsg_id, peer_id);
		}
		break;
	}
}

/* Handle incoming factory messages from peers */
static struct command_result *handle_custommsg(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const jsmntok_t *payload_tok, *peer_id_tok;
	const u8 *payload;
	const char *peer_id;
	u16 type, submsg_id;

	peer_id_tok = json_get_member(buf, params, "peer_id");
	payload_tok = json_get_member(buf, params, "payload");
	if (!payload_tok || !peer_id_tok)
		return command_hook_success(cmd);

	peer_id = json_strdup(cmd, buf, peer_id_tok);
	payload = json_tok_bin_from_hex(cmd, buf, payload_tok);
	if (!payload || tal_bytelen(payload) < 4)
		return command_hook_success(cmd);

	type = (payload[0] << 8) | payload[1];
	if (type != FACTORY_MSG_TYPE)
		return command_hook_success(cmd);

	submsg_id = (payload[2] << 8) | payload[3];
	dispatch_blip56_submsg(cmd, peer_id, submsg_id,
			       payload + 4, tal_bytelen(payload) - 4);

	return command_hook_success(cmd);
}

/* Handle openchannel hook — process channel_in_factory TLV (65600) */
static struct command_result *handle_openchannel(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *openchannel, *factory;

	openchannel = json_get_member(buf, params, "openchannel");
	if (!openchannel)
		return command_hook_success(cmd);

	factory = json_get_member(buf, openchannel, "channel_in_factory");
	if (!factory)
		return command_hook_success(cmd);

	/* Extract factory_protocol_id (32 bytes) and factory_instance_id (32 bytes) */
	const jsmntok_t *proto_tok = json_get_member(buf, factory,
						      "factory_protocol_id");
	const jsmntok_t *inst_tok = json_get_member(buf, factory,
						     "factory_instance_id");
	const jsmntok_t *warn_tok = json_get_member(buf, factory,
						     "factory_early_warning_time");

	if (proto_tok && inst_tok) {
		const char *proto_hex = json_strdup(cmd, buf, proto_tok);
		const char *inst_hex = json_strdup(cmd, buf, inst_tok);

		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory channel open: proto=%s inst=%s",
			   proto_hex ? proto_hex : "?",
			   inst_hex ? inst_hex : "?");

		/* Validate protocol ID */
		if (proto_hex && strlen(proto_hex) == 64) {
			uint8_t proto_id[32];
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				sscanf(proto_hex + j*2, "%02x", &b);
				proto_id[j] = (uint8_t)b;
			}
			if (memcmp(proto_id, SUPERSCALAR_PROTOCOL_ID, 32) != 0) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Unknown factory protocol, rejecting");
				return command_hook_success(cmd);
			}
		}

		/* Find factory by instance_id and map channel */
		if (inst_hex && strlen(inst_hex) == 64) {
			uint8_t inst_id[32];
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				sscanf(inst_hex + j*2, "%02x", &b);
				inst_id[j] = (uint8_t)b;
			}
			factory_instance_t *fi = ss_factory_find(&ss_state,
								  inst_id);
			if (fi) {
				/* Map this channel to the factory */
				const jsmntok_t *cid_tok = json_get_member(buf,
					openchannel, "channel_id");
				if (cid_tok) {
					const char *cid_hex = json_strdup(cmd,
						buf, cid_tok);
					uint8_t cid[32];
					if (cid_hex && strlen(cid_hex) == 64) {
						for (int j = 0; j < 32; j++) {
							unsigned int b;
							sscanf(cid_hex + j*2,
								"%02x", &b);
							cid[j] = (uint8_t)b;
						}
						ss_factory_map_channel(fi, cid,
							fi->n_channels, 0);
						plugin_log(plugin_handle,
							   LOG_INFORM,
							   "Mapped channel to "
							   "factory leaf %zu",
							   fi->n_channels - 1);
					}
				}

				if (warn_tok) {
					u32 ewt;
					json_to_u32(buf, warn_tok, &ewt);
					fi->early_warning_time = (uint16_t)ewt;
				}

				fi->lifecycle = FACTORY_LIFECYCLE_ACTIVE;
			} else {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Factory instance not found for "
					   "channel open");
			}
		}
	} else {
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory channel open detected (no TLV fields)");
	}

	return command_hook_success(cmd);
}

/* factory-create RPC — LSP creates a new factory (Phase 1)
 * Takes client node IDs and creates the DW tree. */
static struct command_result *json_factory_create(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *params)
{
	const jsmntok_t *clients_tok;
	u64 *funding_sats;
	factory_instance_t *fi;
	secp256k1_context *secp_ctx;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("funding_sats", param_u64, &funding_sats),
		   p_req("clients", param_array, &clients_tok),
		   NULL))
		return command_param_failed();

	/* Generate random instance_id */
	for (int i = 0; i < 32; i++)
		instance_id[i] = (uint8_t)(random() & 0xFF);

	fi = ss_factory_new(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
				    "Too many active factories");

	fi->is_lsp = true;
	fi->lifecycle = FACTORY_LIFECYCLE_INIT;
	fi->ceremony = CEREMONY_IDLE;

	/* Parse client node IDs */
	const jsmntok_t *t;
	size_t i;
	json_for_each_arr(i, t, clients_tok) {
		if (fi->n_clients >= MAX_FACTORY_PARTICIPANTS)
			break;
		const char *hex = json_strdup(cmd, buf, t);
		if (hex && strlen(hex) == 66) {
			client_state_t *c = &fi->clients[fi->n_clients];
			for (int j = 0; j < 33; j++) {
				unsigned int byte;
				sscanf(hex + j*2, "%02x", &byte);
				c->node_id[j] = (uint8_t)byte;
			}
			c->signer_slot = fi->n_clients + 1; /* 0=LSP */
			fi->n_clients++;
		}
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-create: %zu clients, %"PRIu64" sats",
		   fi->n_clients, *funding_sats);

	/* Initialize the factory via libsuperscalar */
	secp_ctx = global_secp_ctx;

	/* Build pubkey array: [LSP, client0, client1, ...] */
	{
		factory_t *factory = calloc(1, sizeof(factory_t));
		size_t n_total = 1 + fi->n_clients;
		secp256k1_pubkey *pubkeys = calloc(n_total,
						   sizeof(secp256k1_pubkey));

		/* Derive keypairs deterministically from instance_id.
		 * Both sides compute identical keys. */
		for (size_t k = 0; k < n_total; k++) {
			unsigned char sk[32];
			derive_factory_seckey(sk, fi->instance_id, (int)k);
			if (!secp256k1_ec_pubkey_create(secp_ctx,
							&pubkeys[k], sk)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Bad derived pubkey");
			}
		}

		/* Initialize factory with derived pubkeys */
		factory_init_from_pubkeys(factory, secp_ctx,
					  pubkeys, n_total,
					  DW_STEP_BLOCKS,
					  16); /* states_per_layer */

		/* Set arity: 1 client/leaf for 2 participants, 2 for more */
		if (fi->n_clients <= 1) {
			factory_set_arity(factory, FACTORY_ARITY_1);
		} else {
			factory_set_arity(factory, FACTORY_ARITY_2);
		}

		/* Set funding — use a plausible P2TR scriptpubkey.
		 * Real funding comes from the on-chain UTXO backing
		 * the factory. For now use synthetic data. */
		uint8_t synth_txid[32];
		for (int j = 0; j < 32; j++) synth_txid[j] = j + 1;
		/* P2TR scriptpubkey: OP_1 <32-byte x-only key> */
		uint8_t synth_spk[34];
		synth_spk[0] = 0x51; /* OP_1 */
		synth_spk[1] = 0x20; /* PUSH 32 */
		/* Use the aggregate key as the taproot key */
		memset(synth_spk + 2, 0xAA, 32);
		factory_set_funding(factory, synth_txid, 0,
				    *funding_sats, synth_spk, 34);

		/* Build the DW tree */
		int rc = factory_build_tree(factory);
		if (rc == 0) {
			plugin_log(plugin_handle, LOG_BROKEN,
				   "factory_build_tree failed: %d", rc);
			free(factory);
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to build factory tree");
		}

		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory tree built: %zu participants",
			   n_total);

		/* Store factory handle */
		fi->lib_factory = factory;

		/* Initialize signing sessions */
		rc = factory_sessions_init(factory);
		if (rc == 0) {
			plugin_log(plugin_handle, LOG_BROKEN,
				   "factory_sessions_init failed");
			free(factory);
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to init signing sessions");
		}

		/* Generate nonces using nonce pool.
		 * Need a keypair for the LSP (participant 0). */
		{
			unsigned char lsp_seckey[32];
			secp256k1_keypair lsp_keypair;

			/* Derive LSP seckey deterministically (participant 0) */
			derive_factory_seckey(lsp_seckey, fi->instance_id, 0);
			if (!secp256k1_keypair_create(secp_ctx, &lsp_keypair,
						      lsp_seckey)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Failed to create LSP keypair");
			}

			/* Store seckey for signing phase */
			memcpy(fi->our_seckey, lsp_seckey, 32);
			fi->our_participant_idx = 0;
			fi->n_secnonces = 0;

			/* Count nodes where LSP is a signer */
			size_t lsp_node_count = factory_count_nodes_for_participant(
				factory, 0);

			/* Heap-allocate pool so secnonces survive this scope */
			musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
			if (!musig_nonce_pool_generate(secp_ctx, pool,
						       lsp_node_count,
						       lsp_seckey,
						       &pubkeys[0],
						       NULL)) {
				free(pool);
				free(pubkeys);
				return command_fail(cmd, LIGHTNINGD,
						    "Failed to generate nonce pool");
			}
			fi->nonce_pool = pool;

			/* Extract nonces for each node */
			nonce_bundle_t nb;
			memset(&nb, 0, sizeof(nb));
			memcpy(nb.instance_id, fi->instance_id, 32);
			nb.n_participants = n_total;
			nb.n_nodes = factory->n_nodes;
			nb.n_entries = 0;

			/* Include all pubkeys so client can reconstruct */
			for (size_t pk = 0; pk < n_total && pk < MAX_PARTICIPANTS; pk++) {
				size_t pklen = 33;
				secp256k1_ec_pubkey_serialize(secp_ctx,
					nb.pubkeys[pk], &pklen,
					&pubkeys[pk],
					SECP256K1_EC_COMPRESSED);
			}

			size_t pool_entry = 0;
			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, 0);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *secnonce;
				secp256k1_musig_pubnonce pubnonce;

				if (!musig_nonce_pool_next(pool,
							   &secnonce,
							   &pubnonce)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Nonce pool exhausted at node %zu",
						   ni);
					break;
				}

				/* Track pool index → node mapping */
				fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
				fi->secnonce_node_idx[fi->n_secnonces] = ni;
				fi->n_secnonces++;
				pool_entry++;

				/* Set on the factory session */
				factory_session_set_nonce(factory, ni,
							  (size_t)slot,
							  &pubnonce);

				/* Serialize for sending */
				musig_pubnonce_serialize(secp_ctx,
					nb.entries[nb.n_entries].pubnonce,
					&pubnonce);
				nb.entries[nb.n_entries].node_idx = ni;
				nb.entries[nb.n_entries].signer_slot = slot;
				nb.n_entries++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "MuSig2 nonces: %zu entries for %zu nodes",
				   nb.n_entries,
				   (size_t)factory->n_nodes);

			/* Serialize the nonce bundle */
			uint8_t nbuf[MAX_WIRE_BUF];
			size_t blen = nonce_bundle_serialize(&nb, nbuf,
							     sizeof(nbuf));
			plugin_log(plugin_handle, LOG_INFORM,
				   "Nonce bundle serialized: %zu bytes",
				   blen);

			fi->ceremony = CEREMONY_PROPOSED;

			/* Send FACTORY_PROPOSE to each client via piggyback */
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				char client_hex[67];
				for (int h = 0; h < 33; h++)
					sprintf(client_hex + h*2, "%02x",
						fi->clients[ci].node_id[h]);
				send_factory_msg(cmd, client_hex,
					SS_SUBMSG_FACTORY_PROPOSE,
					nbuf, blen);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Sent FACTORY_PROPOSE to client %zu "
					   "(%zu bytes)", ci, blen);
			}
		}

		free(pubkeys);
	}

	{
		char id_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(id_hex + j*2, "%02x", instance_id[j]);

		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_string(js, "instance_id", id_hex);
		json_add_u64(js, "n_clients", fi->n_clients);
		json_add_string(js, "ceremony", "init");
		return command_finished(cmd, js);
	}
}

/* factory-list RPC — show all factory instances */
static struct command_result *json_factory_list(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct json_stream *js;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "factories");
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		char id_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(id_hex + j*2, "%02x", fi->instance_id[j]);

		json_object_start(js, NULL);
		json_add_string(js, "instance_id", id_hex);
		json_add_bool(js, "is_lsp", fi->is_lsp);
		json_add_u32(js, "n_clients", fi->n_clients);
		json_add_u32(js, "epoch", fi->epoch);
		json_add_u32(js, "n_channels", fi->n_channels);
		json_add_string(js, "lifecycle",
			fi->lifecycle == FACTORY_LIFECYCLE_INIT ? "init" :
			fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE ? "active" :
			fi->lifecycle == FACTORY_LIFECYCLE_DYING ? "dying" :
			"expired");
		json_add_string(js, "ceremony",
			fi->ceremony == CEREMONY_IDLE ? "idle" :
			fi->ceremony == CEREMONY_PROPOSED ? "proposed" :
			fi->ceremony == CEREMONY_NONCES_COLLECTED ? "nonces_collected" :
			fi->ceremony == CEREMONY_PSIGS_COLLECTED ? "psigs_collected" :
			fi->ceremony == CEREMONY_COMPLETE ? "complete" :
			fi->ceremony == CEREMONY_ROTATING ? "rotating" :
			fi->ceremony == CEREMONY_ROTATE_COMPLETE ? "rotate_complete" :
			fi->ceremony == CEREMONY_REVOKED ? "revoked" :
			"failed");
		json_add_u32(js, "max_epochs", fi->max_epochs);
		json_add_u32(js, "creation_block", fi->creation_block);
		json_add_u32(js, "expiry_block", fi->expiry_block);
		json_add_bool(js, "rotation_in_progress",
			fi->rotation_in_progress);
		json_add_u32(js, "n_breach_epochs", fi->n_breach_epochs);

		/* Distribution TX status */
		factory_t *lf = (factory_t *)fi->lib_factory;
		if (lf) {
			json_add_string(js, "dist_tx_status",
				lf->dist_tx_ready == 2 ? "signed" :
				lf->dist_tx_ready == 1 ? "unsigned" :
				"none");
			json_add_u32(js, "tree_nodes", lf->n_nodes);
		}

		/* Funding info */
		if (fi->funding_txid[0] || fi->funding_txid[1]) {
			char ftxid[65];
			for (int j = 0; j < 32; j++)
				sprintf(ftxid + j*2, "%02x",
					fi->funding_txid[31-j]);
			json_add_string(js, "funding_txid", ftxid);
			json_add_u32(js, "funding_outnum", fi->funding_outnum);
		}

		/* Channel mappings */
		if (fi->n_channels > 0) {
			json_array_start(js, "channels");
			for (size_t ch = 0; ch < fi->n_channels; ch++) {
				char cid[65];
				for (int j = 0; j < 32; j++)
					sprintf(cid + j*2, "%02x",
						fi->channels[ch].channel_id[j]);
				json_object_start(js, NULL);
				json_add_string(js, "channel_id", cid);
				json_add_u32(js, "leaf_index",
					fi->channels[ch].leaf_index);
				json_add_u32(js, "leaf_side",
					fi->channels[ch].leaf_side);
				json_object_end(js);
			}
			json_array_end(js);
		}
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* factory-close RPC — LSP initiates cooperative close.
 * Splits factory value equally among participants (demo). */
static struct command_result *json_factory_close(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can close");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	secp256k1_context *ctx = global_secp_ctx;
	size_t n_participants = 1 + fi->n_clients;

	/* Build output distribution using the library's balance-aware
	 * function. Falls back to equal split if no client amounts
	 * are provided (NULL). Fee set to 500 sats. */
	tx_output_t outputs[MAX_DIST_OUTPUTS];
	size_t n_outputs = factory_compute_distribution_outputs(
		factory, outputs, MAX_DIST_OUTPUTS, 500);
	if (n_outputs == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to compute close distribution");

	/* Re-init just node 0 for close signing */
	factory_session_init_node(factory, 0);

	/* Generate LSP nonces */
	unsigned char lsp_seckey[32];
	derive_factory_seckey(lsp_seckey, fi->instance_id, 0);
	memcpy(fi->our_seckey, lsp_seckey, 32);
	fi->our_participant_idx = 0;

	secp256k1_pubkey lsp_pub;
	if (!secp256k1_ec_pubkey_create(ctx, &lsp_pub, lsp_seckey))
		return command_fail(cmd, LIGHTNINGD, "Bad LSP close pubkey");

	if (fi->nonce_pool) free(fi->nonce_pool);
	musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
	musig_nonce_pool_generate(ctx, pool, 1, lsp_seckey, &lsp_pub, NULL);
	fi->nonce_pool = pool;
	fi->n_secnonces = 0;

	secp256k1_musig_secnonce *secnonce;
	secp256k1_musig_pubnonce pubnonce;
	musig_nonce_pool_next(pool, &secnonce, &pubnonce);
	fi->secnonce_pool_idx[0] = 0;
	fi->secnonce_node_idx[0] = 0;
	fi->n_secnonces = 1;
	factory_session_set_nonce(factory, 0, 0, &pubnonce);

	/* Build CLOSE_PROPOSE payload:
	 * n_outputs(4) + per output: amount(8) + spk_len(2) + spk(var)
	 * + nonce_bundle */
	uint8_t payload[4096];
	uint8_t *p = payload;
	p[0] = 0; p[1] = 0; p[2] = 0; p[3] = (uint8_t)n_outputs;
	p += 4;
	for (size_t k = 0; k < n_outputs; k++) {
		uint64_t amt = outputs[k].amount_sats;
		p[0] = (amt >> 56) & 0xFF; p[1] = (amt >> 48) & 0xFF;
		p[2] = (amt >> 40) & 0xFF; p[3] = (amt >> 32) & 0xFF;
		p[4] = (amt >> 24) & 0xFF; p[5] = (amt >> 16) & 0xFF;
		p[6] = (amt >> 8) & 0xFF;  p[7] = amt & 0xFF;
		p += 8;
		uint16_t sl = (uint16_t)outputs[k].script_pubkey_len;
		p[0] = (sl >> 8) & 0xFF; p[1] = sl & 0xFF;
		p += 2;
		memcpy(p, outputs[k].script_pubkey, sl);
		p += sl;
	}

	/* Append nonce bundle */
	nonce_bundle_t nb;
	memset(&nb, 0, sizeof(nb));
	memcpy(nb.instance_id, fi->instance_id, 32);
	nb.n_participants = n_participants;
	nb.n_nodes = 1;
	nb.n_entries = 1;
	nb.entries[0].node_idx = 0;
	nb.entries[0].signer_slot = 0;
	musig_pubnonce_serialize(ctx, nb.entries[0].pubnonce, &pubnonce);

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		unsigned char sk2[32];
		derive_factory_seckey(sk2, fi->instance_id, (int)pk);
		secp256k1_pubkey ppk;
		if (!secp256k1_ec_pubkey_create(ctx, &ppk, sk2))
			continue;
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx, nb.pubkeys[pk], &pklen,
			&ppk, SECP256K1_EC_COMPRESSED);
	}

	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(&nb, nbuf, sizeof(nbuf));
	memcpy(p, nbuf, nlen);
	size_t plen = (size_t)(p - payload) + nlen;

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char client_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(client_hex + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		client_hex[66] = '\0';
		send_factory_msg(cmd, client_hex,
			SS_SUBMSG_CLOSE_PROPOSE,
			payload, plen);
	}

	fi->lifecycle = FACTORY_LIFECYCLE_DYING;

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-close: sent CLOSE_PROPOSE to %zu clients",
		   fi->n_clients);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "status", "close_proposed");
	return command_finished(cmd, js);
}

/* factory-rotate RPC — LSP advances DW epoch and re-signs.
 * Takes instance_id of an existing factory. */
static struct command_result *json_factory_rotate(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can rotate");
	if (fi->ceremony != CEREMONY_COMPLETE &&
	    fi->ceremony != CEREMONY_ROTATE_COMPLETE &&
	    fi->ceremony != CEREMONY_REVOKED)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory not in signed state");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	secp256k1_context *ctx = global_secp_ctx;
	uint32_t old_epoch = fi->epoch;

	/* Generate revocation secret for current epoch before advancing */
	if (factory->n_revocation_secrets == 0)
		factory_generate_flat_secrets(factory, 256);

	/* Advance the DW counter */
	if (!dw_counter_advance(&factory->counter)) {
		return command_fail(cmd, LIGHTNINGD,
				    "DW counter exhausted, cannot rotate");
	}
	fi->epoch = dw_counter_epoch(&factory->counter);

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-rotate: epoch %u → %u",
		   old_epoch, fi->epoch);

	/* Rebuild all node transactions for new epoch */
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory_rebuild_node_tx(factory, ni)) {
			plugin_log(plugin_handle, LOG_BROKEN,
				   "factory-rotate: rebuild node %zu failed", ni);
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to rebuild tree");
		}
	}

	/* Re-initialize signing sessions */
	if (!factory_sessions_init(factory))
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to reinit signing sessions");

	/* Generate new nonces (same flow as factory-create) */
	unsigned char lsp_seckey[32];
	derive_factory_seckey(lsp_seckey, fi->instance_id, 0);

	size_t n_participants = 1 + fi->n_clients;
	secp256k1_pubkey *pubkeys = calloc(n_participants,
					   sizeof(secp256k1_pubkey));
	for (size_t k = 0; k < n_participants; k++) {
		unsigned char sk[32];
		derive_factory_seckey(sk, fi->instance_id, (int)k);
		if (!secp256k1_ec_pubkey_create(ctx, &pubkeys[k], sk)) {
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "Bad rotate pubkey");
		}
	}

	/* Store seckey for signing */
	memcpy(fi->our_seckey, lsp_seckey, 32);
	fi->our_participant_idx = 0;
	fi->n_secnonces = 0;

	/* Free old nonce pool if any */
	if (fi->nonce_pool) {
		free(fi->nonce_pool);
		fi->nonce_pool = NULL;
	}

	size_t lsp_node_count = factory_count_nodes_for_participant(factory, 0);
	musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
	if (!musig_nonce_pool_generate(ctx, pool, lsp_node_count,
				       lsp_seckey, &pubkeys[0], NULL)) {
		free(pool);
		free(pubkeys);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to generate nonce pool");
	}
	fi->nonce_pool = pool;

	/* Build nonce bundle for rotation */
	nonce_bundle_t nb;
	memset(&nb, 0, sizeof(nb));
	memcpy(nb.instance_id, fi->instance_id, 32);
	nb.n_participants = n_participants;
	nb.n_nodes = factory->n_nodes;
	nb.n_entries = 0;

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx,
			nb.pubkeys[pk], &pklen,
			&pubkeys[pk], SECP256K1_EC_COMPRESSED);
	}

	size_t pool_entry = 0;
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		int slot = factory_find_signer_slot(factory, ni, 0);
		if (slot < 0) continue;

		secp256k1_musig_secnonce *secnonce;
		secp256k1_musig_pubnonce pubnonce;
		if (!musig_nonce_pool_next(pool, &secnonce, &pubnonce))
			break;

		fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
		fi->secnonce_node_idx[fi->n_secnonces] = ni;
		fi->n_secnonces++;
		pool_entry++;

		factory_session_set_nonce(factory, ni, (size_t)slot, &pubnonce);
		musig_pubnonce_serialize(ctx,
			nb.entries[nb.n_entries].pubnonce, &pubnonce);
		nb.entries[nb.n_entries].node_idx = ni;
		nb.entries[nb.n_entries].signer_slot = slot;
		nb.n_entries++;
	}

	/* Serialize and send ROTATE_PROPOSE to all clients.
	 * Payload: [4 bytes: old_epoch] [4 bytes: new_epoch] + nonce_bundle */
	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(&nb, nbuf, sizeof(nbuf));

	/* Prepend epoch info: old(4) + new(4) + bundle */
	uint8_t payload[8 + MAX_WIRE_BUF];
	payload[0] = (old_epoch >> 24) & 0xFF;
	payload[1] = (old_epoch >> 16) & 0xFF;
	payload[2] = (old_epoch >> 8) & 0xFF;
	payload[3] = old_epoch & 0xFF;
	payload[4] = (fi->epoch >> 24) & 0xFF;
	payload[5] = (fi->epoch >> 16) & 0xFF;
	payload[6] = (fi->epoch >> 8) & 0xFF;
	payload[7] = fi->epoch & 0xFF;
	memcpy(payload + 8, nbuf, nlen);
	size_t plen = 8 + nlen;

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char client_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(client_hex + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		client_hex[66] = '\0';
		send_factory_msg(cmd, client_hex,
			SS_SUBMSG_ROTATE_PROPOSE,
			payload, plen);
	}

	/* Reset ceremony tracking for rotation */
	ss_factory_reset_ceremony(fi);
	fi->ceremony = CEREMONY_ROTATING;

	free(pubkeys);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "old_epoch", old_epoch);
	json_add_u32(js, "new_epoch", fi->epoch);
	json_add_string(js, "ceremony", "rotating");
	return command_finished(cmd, js);
}

/* factory-force-close RPC — broadcast signed DW tree for unilateral close.
 * Extracts signed txs from factory nodes and sends via sendrawtransaction. */
static struct command_result *json_factory_force_close(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	/* Extract and broadcast signed transactions.
	 * DW tree: kickoff first, then state nodes in order. */
	size_t broadcast_count = 0;
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory->nodes[ni].is_signed) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "force-close: node %zu not signed, skipping",
				   ni);
			continue;
		}

		tx_buf_t *stx = &factory->nodes[ni].signed_tx;
		if (!stx->data || stx->len == 0)
			continue;

		/* Convert to hex for sendrawtransaction */
		char *tx_hex = tal_arr(cmd, char, stx->len * 2 + 1);
		for (size_t h = 0; h < stx->len; h++)
			sprintf(tx_hex + h*2, "%02x", stx->data[h]);

		/* Store txid for breach monitoring */
		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x",
				factory->nodes[ni].txid[31 - j]);

		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: node %zu "
			   "(%s, %zu bytes, txid=%s)",
			   ni,
			   factory->nodes[ni].type == 0 ? "kickoff" : "state",
			   stx->len, txid_hex);

		/* Broadcast via sendrawtransaction */
		struct out_req *breq = jsonrpc_request_start(
			cmd, "sendrawtransaction",
			rpc_done, rpc_err, fi);
		json_add_string(breq->js, "tx", tx_hex);
		send_outreq(breq);
		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: broadcast node %zu (txid=%s)",
			   ni, txid_hex);
		broadcast_count++;
	}

	fi->lifecycle = FACTORY_LIFECYCLE_DYING;

	/* Force-close all LN channels in this factory */
	for (size_t ch = 0; ch < fi->n_channels; ch++) {
		char cid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(cid_hex + j*2, "%02x",
				fi->channels[ch].channel_id[j]);
		struct out_req *creq = jsonrpc_request_start(
			cmd, "close",
			rpc_done, rpc_err, fi);
		json_add_string(creq->js, "id", cid_hex);
		json_add_u32(creq->js, "unilateraltimeout", 1);
		send_outreq(creq);
		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: closing channel %zu", ch);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "force-close: %zu signed transactions ready",
		   broadcast_count);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u64(js, "n_signed_txs", broadcast_count);
	json_add_string(js, "status", "force_close_broadcast");

	/* Include raw txs for manual broadcast */
	json_array_start(js, "transactions");
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory->nodes[ni].is_signed) continue;
		tx_buf_t *stx = &factory->nodes[ni].signed_tx;
		if (!stx->data || stx->len == 0) continue;

		char *tx_hex = tal_arr(cmd, char, stx->len * 2 + 1);
		for (size_t h = 0; h < stx->len; h++)
			sprintf(tx_hex + h*2, "%02x", stx->data[h]);

		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x",
				factory->nodes[ni].txid[31 - j]);

		json_object_start(js, NULL);
		json_add_u32(js, "node_idx", ni);
		json_add_string(js, "type",
			factory->nodes[ni].type == 0 ? "kickoff" : "state");
		json_add_string(js, "txid", txid_hex);
		json_add_string(js, "raw_tx", tx_hex);
		json_add_u64(js, "tx_len", stx->len);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* Handle block_added notification — check for breach (old state on-chain).
 * For each factory with breach data, check if any old-epoch txids appeared. */
static struct command_result *handle_block_added(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *block_tok = json_get_member(buf, params, "block");
	if (block_tok) {
		const jsmntok_t *height_tok = json_get_member(buf, block_tok,
							       "height");
		if (height_tok) {
			u32 height;
			json_to_u32(buf, height_tok, &height);
			ss_state.current_blockheight = height;
		}
	}

	/* Check factory lifecycle warnings */
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		if (fi->lifecycle != FACTORY_LIFECYCLE_ACTIVE &&
		    fi->lifecycle != FACTORY_LIFECYCLE_DYING)
			continue;

		if (ss_factory_should_close(fi, ss_state.current_blockheight)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY EXPIRED: factory %zu expired at "
				   "block %u (current: %u) — force-close needed",
				   i, fi->expiry_block,
				   ss_state.current_blockheight);
			fi->lifecycle = FACTORY_LIFECYCLE_DYING;
		} else if (ss_factory_should_warn(fi,
				ss_state.current_blockheight)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Factory %zu approaching expiry at block %u "
				   "(current: %u, warning_time=%u)",
				   i, fi->expiry_block,
				   ss_state.current_blockheight,
				   fi->early_warning_time);
		}
	}

	return notification_handled(cmd);
}

/* factory-check-breach RPC — check if a txid matches an old epoch
 * and build penalty tx if so. */
static struct command_result *json_factory_check_breach(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	const char *id_hex;
	const char *txid_hex;
	u32 *vout;
	u64 *amount_sats;
	u32 *epoch;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("txid", param_string, &txid_hex),
		   p_req("vout", param_u32, &vout),
		   p_req("amount_sats", param_u64, &amount_sats),
		   p_req("epoch", param_u32, &epoch),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory");

	/* Parse the L-stock txid */
	uint8_t l_txid[32];
	if (strlen(txid_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad txid");
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(txid_hex + j*2, "%02x", &b);
		l_txid[31 - j] = (uint8_t)b; /* internal byte order */
	}

	/* Build burn tx for the specified epoch */
	tx_buf_t burn_tx;
	tx_buf_init(&burn_tx, 256);

	if (!factory_build_burn_tx(factory, &burn_tx,
				    l_txid, *vout, *amount_sats,
				    *epoch)) {
		tx_buf_free(&burn_tx);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to build burn tx (no revocation "
				    "secret for epoch %u?)", *epoch);
	}

	/* Convert to hex */
	char *burn_hex = tal_arr(cmd, char, burn_tx.len * 2 + 1);
	for (size_t h = 0; h < burn_tx.len; h++)
		sprintf(burn_hex + h*2, "%02x", burn_tx.data[h]);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Breach penalty tx built for epoch %u (%zu bytes)",
		   *epoch, burn_tx.len);

	/* Broadcast penalty TX immediately */
	struct out_req *breq = jsonrpc_request_start(
		cmd, "sendrawtransaction",
		rpc_done, rpc_err, fi);
	json_add_string(breq->js, "tx", burn_hex);
	send_outreq(breq);
	plugin_log(plugin_handle, LOG_INFORM,
		   "Breach penalty tx broadcast for epoch %u", *epoch);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "burn_tx", burn_hex);
	json_add_u64(js, "burn_tx_len", burn_tx.len);
	json_add_u32(js, "epoch", *epoch);
	json_add_string(js, "status", "penalty_broadcast");
	tx_buf_free(&burn_tx);
	return command_finished(cmd, js);
}

/* Handle peer connect — send supported_factory_protocols */
static struct command_result *handle_connect(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	const jsmntok_t *connect_tok = json_get_member(buf, params, "connect");
	if (!connect_tok)
		return notification_handled(cmd);

	const jsmntok_t *id_tok = json_get_member(buf, connect_tok, "id");
	if (!id_tok)
		return notification_handled(cmd);

	const char *peer_id = json_strdup(cmd, buf, id_tok);

	/* Send our supported protocols to the newly connected peer */
	send_supported_protocols(cmd, peer_id);

	return notification_handled(cmd);
}

/* RPC: factory-open-channels
 * Opens LN channels inside a completed factory.
 * Must be called after factory-create ceremony finishes (FACTORY_READY).
 * Separated from ceremony completion so the RPC cmd context stays alive
 * for the async fundchannel_start / fundchannel_complete chain. */
static struct command_result *json_factory_open_channels(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *inst_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   NULL))
		return command_param_failed();

	/* Decode 32-byte instance_id from hex */
	uint8_t instance_id[32];
	if (strlen(inst_hex) != 64) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "instance_id must be 64 hex chars");
	}
	for (int i = 0; i < 32; i++) {
		unsigned int b;
		if (sscanf(inst_hex + i*2, "%02x", &b) != 1)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "instance_id: invalid hex");
		instance_id[i] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "No factory with that instance_id");

	if (fi->ceremony != CEREMONY_COMPLETE)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Factory ceremony not complete (state=%d)",
				    fi->ceremony);

	if (!fi->is_lsp)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Only the LSP opens channels");

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-open-channels: opening channels for %zu clients",
		   fi->n_clients);

	open_factory_channels(cmd, fi);

	return command_still_pending(cmd);
}

/* Plugin init */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;
	ss_state_init(&ss_state);

	global_secp_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	/* Fetch current blockheight and our node_id from lightningd */
	struct node_id our_id;
	u32 blockheight;
	rpc_scan(init_cmd, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%,blockheight:%}",
		 JSON_SCAN(json_to_node_id, &our_id),
		 JSON_SCAN(json_to_u32, &blockheight));
	ss_state.current_blockheight = blockheight;
	memcpy(ss_state.our_node_id, our_id.k, 33);

	/* Derive factory master key from HSM via makesecret */
	struct secret master_secret;
	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "string",
				    "superscalar-factory-key")),
		 "{secret:%}",
		 JSON_SCAN(json_to_secret, &master_secret));
	memcpy(ss_state.factory_master_key, master_secret.data, 32);
	ss_state.has_master_key = true;
	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory master key derived from HSM");

	/* Load persisted factories from datastore */
	ss_load_factories(init_cmd);

	plugin_log(plugin_handle, LOG_INFORM,
		   "SuperScalar factory plugin initialized "
		   "(blockheight=%u, factories=%zu)",
		   ss_state.current_blockheight,
		   ss_state.n_factories);
	return NULL;
}

static const struct plugin_hook hooks[] = {
	{ "custommsg", handle_custommsg },
	{ "openchannel", handle_openchannel },
};

static const struct plugin_command commands[] = {
	{
		"factory-create",
		json_factory_create,
	},
	{
		"factory-list",
		json_factory_list,
	},
	{
		"factory-rotate",
		json_factory_rotate,
	},
	{
		"factory-close",
		json_factory_close,
	},
	{
		"factory-force-close",
		json_factory_force_close,
	},
	{
		"factory-check-breach",
		json_factory_check_breach,
	},
	{
		"factory-open-channels",
		json_factory_open_channels,
	},
};

static const struct plugin_notification notifs[] = {
	{ "block_added", handle_block_added },
	{ "connect", handle_connect },
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* Feature bit 271 (pluggable_channel_factories) is advertised
	 * by the CLN fork's base code in common/features.h.
	 * No need to set it again from the plugin. */

	plugin_main(argv, init,
		    take(NULL),
		    PLUGIN_RESTARTABLE,
		    true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    NULL);
}
