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

#include "ceremony.h"

/* SuperScalar library — linked at build time.
 * Uncomment when wiring up ceremony calls:
 * #include <superscalar/factory.h>
 * #include <superscalar/musig.h>
 * #include <superscalar/dw_state.h>
 */

static struct plugin *plugin_handle;

/* bLIP-56 factory message type */
#define FACTORY_MSG_TYPE	32800

/* Active ceremony state (single factory for now) */
static ceremony_state_t ceremony_state = CEREMONY_IDLE;

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

/* Dispatch SuperScalar protocol submessages */
static void dispatch_superscalar_submsg(struct command *cmd,
					const char *peer_id,
					u16 submsg_id,
					const u8 *data, size_t len)
{
	switch (submsg_id) {
	case SS_SUBMSG_FACTORY_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP proposed a factory.
		 * TODO: parse tree params, initialize factory,
		 * generate nonces, respond with NONCE_BUNDLE */
		ceremony_state = CEREMONY_PROPOSED;
		break;

	case SS_SUBMSG_NONCE_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "NONCE_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent their nonces.
		 * TODO: call factory_session_set_nonce() for this signer,
		 * when all collected, call factory_sessions_finalize(),
		 * send ALL_NONCES to all clients */
		break;

	case SS_SUBMSG_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ALL_NONCES from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP sent aggregated nonces.
		 * TODO: parse aggregated nonces, set on all sessions,
		 * create partial sigs, respond with PSIG_BUNDLE */
		ceremony_state = CEREMONY_NONCES_COLLECTED;
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
		ceremony_state = CEREMONY_COMPLETE;
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

/* Plugin init */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;
	ceremony_state = CEREMONY_IDLE;

	plugin_log(plugin_handle, LOG_INFORM,
		   "SuperScalar factory plugin initialized");
	return NULL;
}

static const struct plugin_hook hooks[] = {
	{ "custommsg", handle_custommsg },
	{ "openchannel", handle_openchannel },
};

static const struct plugin_command commands[] = {
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
