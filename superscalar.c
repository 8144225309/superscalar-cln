/* SuperScalar channel factory plugin for Core Lightning.
 *
 * Links against libsuperscalar.a for DW tree construction,
 * MuSig2 signing, and factory state management.
 *
 * CLN hooks:
 *   custommsg — receives factory_message (32800) from peers
 *   openchannel — detects factory channel opens
 *
 * CLN RPCs used:
 *   factory-send — send factory submessages to peers
 *   factory-change — trigger factory state changes
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

/* SuperScalar library — linked at build time.
 * Headers included when ceremony logic is wired up:
 *   #include <superscalar/factory.h>
 *   #include <superscalar/musig.h>
 *   #include <superscalar/dw_state.h>
 */

static struct plugin *plugin_handle;

/* Factory submessage IDs (bLIP-56) */
#define FACTORY_MSG_TYPE		32800
#define SUBMSG_PROTOCOL_IDS		512
#define SUBMSG_CHANGE_INIT		6
#define SUBMSG_CHANGE_ACK		8
#define SUBMSG_CHANGE_FUNDING		10
#define SUBMSG_CHANGE_CONTINUE		12
#define SUBMSG_CHANGE_LOCKED		14

/* Dispatch factory submessage to the right handler */
static void dispatch_factory_submsg(struct command *cmd,
				    const char *peer_id,
				    u16 submsg_id,
				    const u8 *data, size_t len)
{
	switch (submsg_id) {
	case SUBMSG_PROTOCOL_IDS:
		plugin_log(plugin_handle, LOG_DBG,
			   "Peer %s advertised factory protocols", peer_id);
		/* TODO: check if peer supports superscalar protocol */
		break;

	case SUBMSG_CHANGE_INIT:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory change init from %s", peer_id);
		/* TODO: validate, build DW tree for new state,
		 * respond with SUBMSG_CHANGE_ACK via factory-send */
		break;

	case SUBMSG_CHANGE_ACK:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory change ack from %s", peer_id);
		/* TODO: both sides agreed, compute new funding txid,
		 * send SUBMSG_CHANGE_FUNDING via factory-send */
		break;

	case SUBMSG_CHANGE_FUNDING:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory change funding from %s", peer_id);
		/* TODO: verify funding txid matches ours,
		 * call factory-sign-commitment,
		 * after commitment_signed exchange,
		 * run MuSig2 ceremony for new factory state,
		 * send SUBMSG_CHANGE_CONTINUE when ready */
		break;

	case SUBMSG_CHANGE_CONTINUE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory change continue from %s", peer_id);
		/* TODO: resume channel (exit STFU),
		 * invalidate old factory state via DW advance,
		 * send SUBMSG_CHANGE_LOCKED when old state invalidated */
		break;

	case SUBMSG_CHANGE_LOCKED:
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory change locked from %s", peer_id);
		/* TODO: new factory state is now active,
		 * discard old state */
		break;

	default:
		/* Unknown submessage — may be from a different factory protocol.
		 * Could also be piggybacked data for MuSig2 nonces/psigs. */
		plugin_log(plugin_handle, LOG_DBG,
			   "Unknown factory submsg %u from %s (len=%zu)",
			   submsg_id, peer_id, len);
		break;
	}
}

/* Handle incoming factory messages from peers via custommsg hook */
static struct command_result *handle_custommsg(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const jsmntok_t *payload_tok, *peer_id_tok;
	const u8 *payload;
	const char *peer_id;
	u16 type;

	peer_id_tok = json_get_member(buf, params, "peer_id");
	payload_tok = json_get_member(buf, params, "payload");
	if (!payload_tok || !peer_id_tok)
		return command_hook_success(cmd);

	peer_id = json_strdup(cmd, buf, peer_id_tok);
	payload = json_tok_bin_from_hex(cmd, buf, payload_tok);
	if (!payload || tal_bytelen(payload) < 4)
		return command_hook_success(cmd);

	/* Check if this is a factory message (type 32800 = 0x8020) */
	type = (payload[0] << 8) | payload[1];
	if (type != FACTORY_MSG_TYPE)
		return command_hook_success(cmd);

	/* Extract submessage_id and dispatch */
	u16 submsg_id = (payload[2] << 8) | payload[3];
	dispatch_factory_submsg(cmd, peer_id,
				submsg_id,
				payload + 4,
				tal_bytelen(payload) - 4);

	return command_hook_success(cmd);
}

/* Handle openchannel hook — detect factory channel opens */
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

	/* TODO: validate factory_protocol_id matches superscalar,
	 * look up factory_instance_id,
	 * initialize channel state from factory leaf */

	return command_hook_success(cmd);
}

/* Plugin init */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;
	plugin_log(plugin_handle, LOG_INFORM,
		   "SuperScalar factory plugin initialized");

	return NULL;
}

static const struct plugin_hook hooks[] = {
	{
		"custommsg",
		handle_custommsg,
	},
	{
		"openchannel",
		handle_openchannel,
	},
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
		    NULL,
		    0,
		    NULL);
}
