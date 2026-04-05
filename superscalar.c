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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <secp256k1.h>

#include "ceremony.h"
#include "factory_state.h"
#include "nonce_exchange.h"

/* SuperScalar library */
#include <superscalar/factory.h>
#include <superscalar/musig.h>
#include <superscalar/dw_state.h>

static struct plugin *plugin_handle;
static superscalar_state_t ss_state;
static secp256k1_context *global_secp_ctx;

/* bLIP-56 factory message type */
#define FACTORY_MSG_TYPE	32800

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
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "RPC %s failed", method);
	return command_still_pending(cmd);
}

/* Send a factory submessage to a peer via factory-send RPC.
 * Used by ceremony handlers when responding to protocol messages. */
#if 0 /* Enable when ceremony logic is wired up */
static struct command_result *
send_factory_submsg(struct command *cmd,
		    const char *channel_id,
		    u16 submsg_id,
		    const u8 *data, size_t len)
{
	struct out_req *req;
	char *hex;

	req = jsonrpc_request_start(cmd->plugin, cmd, "factory-send",
				    NULL, NULL, NULL);
	json_add_string(req->js, "channel_id", channel_id);
	json_add_u64(req->js, "submessage_id", submsg_id);

	hex = tal_hexstr(cmd, data, len);
	json_add_string(req->js, "data", hex);

	return send_outreq(cmd->plugin, req);
}
#endif

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
	if (len >= 32 && submsg_id != SS_SUBMSG_FACTORY_PROPOSE) {
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

			/* We need our secret key for nonce generation.
			 * Find which participant we are. */
			unsigned char our_sec[32];
			int our_idx = -1;
			FILE *ur = fopen("/dev/urandom", "r");
			if (ur) {
				if (fread(our_sec, 1, 32, ur) != 32)
					memset(our_sec, 0x42, 32);
				fclose(ur);
			}
			/* For now we're participant 1 (first client) */
			our_idx = 1;

			/* NOTE: The secret key doesn't match the pubkey
			 * from the bundle. For real operation, the client
			 * would have sent their pubkey to the LSP during
			 * a registration step, and the LSP includes it in
			 * the propose. For the demo, the LSP generated the
			 * client's key — both sides know it. */

			/* Init and build tree with LSP's pubkeys */
			factory_t *factory = calloc(1, sizeof(factory_t));
			factory_init_from_pubkeys(factory, ctx,
				pubkeys, nb.n_participants,
				144, 16);
			if (nb.n_participants <= 2)
				factory_set_arity(factory, FACTORY_ARITY_1);
			else
				factory_set_arity(factory, FACTORY_ARITY_2);

			uint8_t synth_txid[32], synth_spk[34];
			for (int j = 0; j < 32; j++) synth_txid[j] = j + 1;
			synth_spk[0] = 0x51; synth_spk[1] = 0x20;
			memset(synth_spk + 2, 0xAA, 32);
			factory_set_funding(factory, synth_txid, 0,
					    1000000, synth_spk, 34);

			if (!factory_build_tree(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: factory_build_tree failed");
				/* ctx is global */
				free(factory);
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
			musig_nonce_pool_t pool;
			musig_nonce_pool_generate(ctx, &pool,
				our_node_count, our_sec,
				&pubkeys[our_idx], NULL);

			nonce_bundle_t resp;
			memcpy(resp.instance_id, fi->instance_id, 32);
			resp.n_participants = nb.n_participants;
			resp.n_nodes = factory->n_nodes;
			resp.n_entries = 0;

			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *sec;
				secp256k1_musig_pubnonce pub;
				if (!musig_nonce_pool_next(&pool, &sec, &pub))
					break;

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
			uint8_t rbuf[32768];
			size_t rlen = nonce_bundle_serialize(&resp,
				rbuf, sizeof(rbuf));

			/* Build wire message: type(2) + submsg(2) + payload */
			uint8_t wire[4 + 32768];
			wire[0] = 0x80; wire[1] = 0x20;
			wire[2] = 0x01; wire[3] = 0x01; /* NONCE_BUNDLE */
			memcpy(wire + 4, rbuf, rlen);

			char *hex = tal_arr(cmd, char, (4+rlen)*2 + 1);
			for (size_t h = 0; h < 4+rlen; h++)
				sprintf(hex + h*2, "%02x", wire[h]);

			struct out_req *req = jsonrpc_request_start(cmd,
				"sendcustommsg", rpc_done, rpc_err, cmd);
			json_add_string(req->js, "node_id", peer_id);
			json_add_string(req->js, "msg", hex);
			send_outreq(req);

			fi->ceremony = CEREMONY_PROPOSED;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent NONCE_BUNDLE (%zu bytes)",
				   4 + rlen);

			/* ctx is global */
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
			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					cnb.entries[e].pubnonce);
				factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot,
					&pn);
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
				   "LSP: set %zu client nonces",
				   cnb.n_entries);

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

				/* TODO: call factory_sessions_finalize(f)
				 * when session state is fully populated.
				 * Currently crashes because not all signer
				 * nonce slots are initialized — needs
				 * debugging of slot numbering. */

				fi->ceremony = CEREMONY_NONCES_COLLECTED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: all nonces received, ceremony=nonces_collected"
					   " (finalize deferred)");

				/* TODO: serialize ALL_NONCES (aggregated)
				 * and send to all clients.
				 * Then clients create partial sigs. */
			}

			/* ctx is global */
		}
		break;

	case SS_SUBMSG_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ALL_NONCES from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP sent aggregated nonces.
		 * TODO: parse aggregated nonces, set on all sessions,
		 * create partial sigs, respond with PSIG_BUNDLE */
		if (fi) fi->ceremony = CEREMONY_NONCES_COLLECTED;
		break;

	case SS_SUBMSG_PSIG_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "PSIG_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent partial sigs.
		 * TODO: call factory_session_set_partial_sig() for signer,
		 * when all collected, call factory_sessions_complete(),
		 * send FACTORY_READY to all clients */
		break;

	case SS_SUBMSG_FACTORY_READY:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_READY from %s (len=%zu)",
			   peer_id, len);
		/* Client side: factory tree is fully signed.
		 * TODO: verify factory, open channel via CLN with
		 * channel_in_factory TLV */
		if (fi) fi->ceremony = CEREMONY_COMPLETE;
		break;

	case SS_SUBMSG_CLOSE_PROPOSE:
	case SS_SUBMSG_CLOSE_NONCE:
	case SS_SUBMSG_CLOSE_ALL_NONCES:
	case SS_SUBMSG_CLOSE_PSIG:
	case SS_SUBMSG_CLOSE_DONE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Close ceremony submsg 0x%04x from %s",
			   submsg_id, peer_id);
		/* TODO: cooperative close ceremony */
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
	case 6: /* factory_change_init */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_init from %s", peer_id);
		/* TODO: validate, ack via factory-send submsg 8 */
		break;
	case 8: /* factory_change_ack */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_ack from %s", peer_id);
		break;
	case 10: /* factory_change_funding */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_funding from %s", peer_id);
		break;
	case 12: /* factory_change_continue */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_continue from %s", peer_id);
		break;
	case 14: /* factory_change_locked */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_locked from %s", peer_id);
		break;
	case 512: /* factory_protocol_ids */
		plugin_log(plugin_handle, LOG_DBG,
			   "protocol_ids from %s", peer_id);
		break;
	default:
		/* Might be a SuperScalar protocol submessage */
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

/* Handle openchannel hook */
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

	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory channel open detected");
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

		/* LSP pubkey: use our node_id from global state.
		 * If not set yet, generate a temporary keypair. */
		if (ss_state.our_node_id[0] == 0) {
			/* Generate a random keypair for the LSP */
			unsigned char seckey[32];
			FILE *urand = fopen("/dev/urandom", "r");
			if (urand) {
				if (fread(seckey, 1, 32, urand) != 32)
					memset(seckey, 0x42, 32);
				fclose(urand);
			}
			if (!secp256k1_ec_pubkey_create(secp_ctx,
						        &pubkeys[0], seckey))
				memset(&pubkeys[0], 0, sizeof(pubkeys[0]));
			/* Store compressed form */
			size_t clen = 33;
			secp256k1_ec_pubkey_serialize(secp_ctx,
				ss_state.our_node_id, &clen,
				&pubkeys[0],
				SECP256K1_EC_COMPRESSED);
		} else {
			/* Parse our stored compressed pubkey */
			if (!secp256k1_ec_pubkey_parse(secp_ctx,
				&pubkeys[0],
				ss_state.our_node_id, 33)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Invalid LSP pubkey");
			}
		}

		/* Parse client pubkeys from their node IDs */
		for (size_t k = 0; k < fi->n_clients; k++) {
			if (!secp256k1_ec_pubkey_parse(secp_ctx,
				&pubkeys[k + 1],
				fi->clients[k].node_id, 33)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Invalid pubkey for client %zu", k);
				return command_fail(cmd, LIGHTNINGD,
						    "Invalid client pubkey");
			}
		}

		/* Initialize factory with real pubkeys */
		factory_init_from_pubkeys(factory, secp_ctx,
					  pubkeys, n_total,
					  144, /* step_blocks: 1 day */
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
			/* secp context is global, not destroyed */
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
			/* secp context is global, not destroyed */
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to init signing sessions");
		}

		/* Generate nonces using nonce pool.
		 * Need a keypair for the LSP (participant 0). */
		{
			musig_nonce_pool_t pool;
			unsigned char lsp_seckey[32];
			secp256k1_keypair lsp_keypair;

			/* Get LSP seckey (generated at init) */
			FILE *urand2 = fopen("/dev/urandom", "r");
			if (urand2) {
				if (fread(lsp_seckey, 1, 32, urand2) != 32)
					memset(lsp_seckey, 0x42, 32);
				fclose(urand2);
			}
			if (!secp256k1_keypair_create(secp_ctx, &lsp_keypair,
						      lsp_seckey)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Failed to create LSP keypair");
			}

			/* Count nodes where LSP is a signer */
			size_t lsp_node_count = factory_count_nodes_for_participant(
				factory, 0);

			/* Generate nonce pool */
			if (!musig_nonce_pool_generate(secp_ctx, &pool,
						       lsp_node_count,
						       lsp_seckey,
						       &pubkeys[0],
						       NULL)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Failed to generate nonce pool");
			}

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

			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, 0);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *secnonce;
				secp256k1_musig_pubnonce pubnonce;

				if (!musig_nonce_pool_next(&pool,
							   &secnonce,
							   &pubnonce)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Nonce pool exhausted at node %zu",
						   ni);
					break;
				}

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
			uint8_t nbuf[32768];
			size_t blen = nonce_bundle_serialize(&nb, nbuf,
							     sizeof(nbuf));
			plugin_log(plugin_handle, LOG_INFORM,
				   "Nonce bundle serialized: %zu bytes",
				   blen);

			fi->ceremony = CEREMONY_PROPOSED;

			/* Send FACTORY_PROPOSE to each client.
			 * Wire format: factory_message(32800) header
			 *   [2 bytes: type 0x8020]
			 *   [2 bytes: submsg_id 0x0100]
			 *   [payload: nonce bundle] */
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				/* Build the full wire message */
				uint8_t wire[4 + sizeof(nbuf)];
				wire[0] = 0x80; wire[1] = 0x20; /* type 32800 */
				wire[2] = 0x01; wire[3] = 0x00; /* submsg 0x0100 */
				memcpy(wire + 4, nbuf, blen);
				size_t wire_len = 4 + blen;

				/* Convert to hex for sendcustommsg */
				char *hex = tal_arr(cmd, char, wire_len * 2 + 1);
				for (size_t h = 0; h < wire_len; h++)
					sprintf(hex + h*2, "%02x", wire[h]);

				/* Convert client node_id to hex */
				char client_hex[67];
				for (int h = 0; h < 33; h++)
					sprintf(client_hex + h*2, "%02x",
						fi->clients[ci].node_id[h]);

				/* Send via sendcustommsg RPC */
				struct out_req *req;
				req = jsonrpc_request_start(cmd,
					"sendcustommsg",
					rpc_done, rpc_err, cmd);
				json_add_string(req->js, "node_id",
						client_hex);
				json_add_string(req->js, "msg", hex);
				send_outreq(req);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Sent FACTORY_PROPOSE to client %zu "
					   "(%zu bytes)", ci, wire_len);
			}
		}
	}

	/* secp context is global, not destroyed */

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
			"failed");
		json_add_u32(js, "expiry_block", fi->expiry_block);
		json_add_u32(js, "n_breach_epochs", fi->n_breach_epochs);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* Plugin init */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;
	ss_state_init(&ss_state);

	/* TODO: load factory instances from CLN datastore */

	global_secp_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	plugin_log(plugin_handle, LOG_INFORM,
		   "SuperScalar factory plugin initialized (%zu factories)",
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
};

static const struct plugin_notification notifs[] = {
};

int main(int argc, char *argv[])
{
	setup_locale();
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
