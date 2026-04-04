/* Persistence layer for SuperScalar factory state.
 *
 * Uses CLN's datastore RPC for key-value storage.
 * Schema:
 *   superscalar/factories/{instance_id_hex}/meta
 *   superscalar/factories/{instance_id_hex}/channels
 *   superscalar/factories/{instance_id_hex}/breach/{epoch}
 */
#ifndef SUPERSCALAR_PERSIST_H
#define SUPERSCALAR_PERSIST_H

#include "factory_state.h"

/* Serialize factory metadata to binary */
size_t ss_persist_serialize_meta(const factory_instance_t *fi,
				 uint8_t **out);

/* Deserialize factory metadata from binary */
bool ss_persist_deserialize_meta(factory_instance_t *fi,
				 const uint8_t *data, size_t len);

/* Serialize channel mappings */
size_t ss_persist_serialize_channels(const factory_instance_t *fi,
				     uint8_t **out);

/* Deserialize channel mappings */
bool ss_persist_deserialize_channels(factory_instance_t *fi,
				     const uint8_t *data, size_t len);

/* Serialize breach data for one epoch */
size_t ss_persist_serialize_breach(const epoch_breach_data_t *bd,
				   uint8_t **out);

/* Deserialize breach data */
bool ss_persist_deserialize_breach(epoch_breach_data_t *bd,
				   const uint8_t *data, size_t len);

/* Build datastore key for a factory */
void ss_persist_key_meta(const factory_instance_t *fi, char *out, size_t len);
void ss_persist_key_channels(const factory_instance_t *fi, char *out, size_t len);
void ss_persist_key_breach(const factory_instance_t *fi, uint32_t epoch,
			   char *out, size_t len);

#endif /* SUPERSCALAR_PERSIST_H */
