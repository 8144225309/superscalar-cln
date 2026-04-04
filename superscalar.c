/* SuperScalar channel factory plugin for Core Lightning.
 *
 * Implements the factory protocol side of bLIP-56 pluggable channel
 * factories using Decker-Wattenhofer state trees with MuSig2.
 *
 * Communicates with CLN via:
 *   - custommsg hook: receives factory_message (32800) from peers
 *   - factory-send RPC: sends factory messages to peers
 *   - factory-change RPC: triggers factory state changes
 *   - openchannel hook: detects factory channel opens
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

/* Factory protocol identifier: SHA256("superscalar/v0") */
static u8 superscalar_protocol_id[32];

/* Active factory instances */
struct factory_instance {
	u8 instance_id[32];
	/* TODO: DW tree state, MuSig2 sessions, timelocks */
};

static struct plugin *plugin_handle;

/* Handle incoming factory messages from peers via custommsg hook */
static struct command_result *handle_custommsg(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const jsmntok_t *payload_tok, *peer_id_tok;
	const u8 *payload;
	u16 type;

	peer_id_tok = json_get_member(buf, params, "peer_id");
	payload_tok = json_get_member(buf, params, "payload");
	if (!payload_tok || !peer_id_tok)
		return command_hook_success(cmd);

	payload = json_tok_bin_from_hex(cmd, buf, payload_tok);
	if (!payload || tal_bytelen(payload) < 4)
		return command_hook_success(cmd);

	/* Check if this is a factory message (type 32800 = 0x8020) */
	type = (payload[0] << 8) | payload[1];
	if (type != 32800)
		return command_hook_success(cmd);

	/* Extract submessage_id */
	u16 submsg_id = (payload[2] << 8) | payload[3];
	plugin_log(plugin_handle, LOG_DBG,
		   "Factory message: submsg=%u len=%zu",
		   submsg_id, tal_bytelen(payload) - 4);

	/* TODO: dispatch to factory protocol handlers based on submsg_id:
	 *   512 = factory_protocol_ids (peer advertising supported protocols)
	 *     6 = factory_change_init
	 *     8 = factory_change_ack
	 *    10 = factory_change_funding
	 *    12 = factory_change_continue
	 *    14 = factory_change_locked
	 */

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
	if (!factory) {
		/* Not a factory channel, pass through */
		return command_hook_success(cmd);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory channel open detected");

	/* TODO: validate factory_protocol_id matches ours,
	 * check factory_instance_id, set up DW tree state */

	return command_hook_success(cmd);
}

/* Plugin init callback */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;

	/* Compute protocol_id = SHA256("superscalar/v0") */
	/* TODO: use proper SHA256 from ccan */
	memset(superscalar_protocol_id, 0, 32);
	superscalar_protocol_id[0] = 0x53; /* 'S' placeholder */

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
		    take(NULL), /* command table */
		    PLUGIN_RESTARTABLE,
		    true, /* init_rpc */
		    NULL, /* features */
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, /* notification topics */
		    0,
		    NULL);
}
