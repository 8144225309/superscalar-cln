/* Factory instance state management */
#include <string.h>
#include <stdlib.h>
#include "factory_state.h"

void ss_state_init(superscalar_state_t *state)
{
	memset(state, 0, sizeof(*state));
}

factory_instance_t *ss_factory_new(superscalar_state_t *state,
				   const uint8_t *instance_id)
{
	factory_instance_t *fi;

	if (state->n_factories >= MAX_FACTORIES)
		return NULL;

	fi = calloc(1, sizeof(*fi));
	if (!fi)
		return NULL;

	memcpy(fi->instance_id, instance_id, 32);
	fi->lifecycle = FACTORY_LIFECYCLE_INIT;
	fi->ceremony = CEREMONY_IDLE;

	state->factories[state->n_factories++] = fi;
	return fi;
}

factory_instance_t *ss_factory_find(superscalar_state_t *state,
				    const uint8_t *instance_id)
{
	for (size_t i = 0; i < state->n_factories; i++) {
		if (memcmp(state->factories[i]->instance_id,
			   instance_id, 32) == 0)
			return state->factories[i];
	}
	return NULL;
}

factory_instance_t *ss_factory_find_by_channel(superscalar_state_t *state,
					       const uint8_t *channel_id)
{
	for (size_t i = 0; i < state->n_factories; i++) {
		factory_instance_t *fi = state->factories[i];
		for (size_t j = 0; j < fi->n_channels; j++) {
			if (memcmp(fi->channels[j].channel_id,
				   channel_id, 32) == 0)
				return fi;
		}
	}
	return NULL;
}

client_state_t *ss_factory_find_client(factory_instance_t *fi,
				       const uint8_t *node_id)
{
	for (size_t i = 0; i < fi->n_clients; i++) {
		if (memcmp(fi->clients[i].node_id, node_id, 33) == 0)
			return &fi->clients[i];
	}
	return NULL;
}

bool ss_factory_all_nonces_received(const factory_instance_t *fi)
{
	for (size_t i = 0; i < fi->n_clients; i++) {
		if (!fi->clients[i].nonce_received)
			return false;
	}
	return fi->n_clients > 0;
}

bool ss_factory_all_psigs_received(const factory_instance_t *fi)
{
	for (size_t i = 0; i < fi->n_clients; i++) {
		if (!fi->clients[i].psig_received)
			return false;
	}
	return fi->n_clients > 0;
}

void ss_factory_reset_ceremony(factory_instance_t *fi)
{
	fi->ceremony = CEREMONY_IDLE;
	fi->ceremony_round = 0;
	for (size_t i = 0; i < fi->n_clients; i++) {
		fi->clients[i].nonce_received = false;
		fi->clients[i].psig_received = false;
	}
}

void ss_factory_add_breach_data(factory_instance_t *fi,
				uint32_t epoch,
				const uint8_t *revocation_secret,
				const uint8_t *commitment_data,
				size_t commitment_data_len)
{
	epoch_breach_data_t *bd;
	size_t new_count = fi->n_breach_epochs + 1;

	epoch_breach_data_t *tmp = realloc(fi->breach_data,
				       new_count * sizeof(epoch_breach_data_t));
	if (!tmp)
		return;
	fi->breach_data = tmp;
	bd = &fi->breach_data[fi->n_breach_epochs];

	bd->epoch = epoch;
	if (revocation_secret) {
		memcpy(bd->revocation_secret, revocation_secret, 32);
		bd->has_revocation = true;
	} else {
		bd->has_revocation = false;
	}

	if (commitment_data && commitment_data_len > 0) {
		bd->commitment_data = malloc(commitment_data_len);
		memcpy(bd->commitment_data, commitment_data, commitment_data_len);
		bd->commitment_data_len = commitment_data_len;
	} else {
		bd->commitment_data = NULL;
		bd->commitment_data_len = 0;
	}

	fi->n_breach_epochs = new_count;
}

void ss_factory_map_channel(factory_instance_t *fi,
			    const uint8_t *channel_id,
			    int leaf_index, int leaf_side)
{
	if (fi->n_channels >= MAX_FACTORY_PARTICIPANTS)
		return;

	channel_leaf_map_t *m = &fi->channels[fi->n_channels];
	memcpy(m->channel_id, channel_id, 32);
	m->leaf_index = leaf_index;
	m->leaf_side = leaf_side;
	fi->n_channels++;
}

bool ss_factory_should_warn(const factory_instance_t *fi,
			    uint32_t current_block)
{
	if (fi->lifecycle != FACTORY_LIFECYCLE_ACTIVE)
		return false;
	if (fi->expiry_block == 0)
		return false;
	return current_block + fi->early_warning_time >= fi->expiry_block;
}

bool ss_factory_should_close(const factory_instance_t *fi,
			     uint32_t current_block)
{
	if (fi->lifecycle != FACTORY_LIFECYCLE_ACTIVE &&
	    fi->lifecycle != FACTORY_LIFECYCLE_DYING)
		return false;
	if (fi->expiry_block == 0)
		return false;
	return current_block >= fi->expiry_block;
}
