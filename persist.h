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
void ss_persist_key_breach_index(const factory_instance_t *fi, char *out, size_t len);
void ss_persist_key_signed_txs(const factory_instance_t *fi, char *out, size_t len);

/* Serialize signed DW tree transactions (for force-close after restart).
 * Format: n_nodes(u16) + for each signed node: node_idx(u16) + txid(32) +
 *         tx_len(u32) + tx_data(tx_len). Only includes nodes where
 *         is_signed==true and signed_tx.len > 0. */
size_t ss_persist_serialize_signed_txs(const void *lib_factory,
                                       uint8_t **out);

/* Deserialize signed TXs into a rebuilt factory_t.
 * Restores signed_tx buffers and sets is_signed flag per node. */
bool ss_persist_deserialize_signed_txs(void *lib_factory,
                                       const uint8_t *data, size_t len);

/* Datastore key for signed distribution TX */
void ss_persist_key_dist_tx(const factory_instance_t *fi, char *out, size_t len);

/* --- Tier 2.6: PS leaf chain persistence ---
 *
 * Each PS leaf advance appends one entry to the chain.  Chain[0] is the
 * initial leaf state (captured after factory_sign_all); chain[1..K] are
 * subsequent advances.  Each entry is its own datastore key so advances
 * don't rewrite the whole chain.
 *
 * Key layout:
 *   superscalar/factories/{iid_hex}/ps_chain/{leaf_node_idx}/{chain_pos}
 *
 * Entry value layout:
 *   u8[32]          txid (internal byte order)
 *   u64 BE          chan_amount_sats
 *   u32 BE          signed_tx_len
 *   u8[signed_tx_len] signed_tx_bytes
 */
void ss_persist_key_ps_chain_entry(const factory_instance_t *fi,
				   uint32_t leaf_node_idx,
				   uint32_t chain_pos,
				   char *out, size_t len);

void ss_persist_key_ps_chain_prefix(const factory_instance_t *fi,
				    char *out, size_t len);

size_t ss_persist_serialize_ps_chain_entry(const uint8_t txid32[32],
					   uint64_t chan_amount_sats,
					   const uint8_t *signed_tx,
					   size_t signed_tx_len,
					   uint8_t **out);

bool ss_persist_deserialize_ps_chain_entry(const uint8_t *data, size_t len,
					   uint8_t txid_out32[32],
					   uint64_t *chan_amount_sats_out,
					   uint8_t **signed_tx_out,
					   size_t *signed_tx_len_out);

/* Serialize signed distribution TX (raw bytes + length) */
size_t ss_persist_serialize_dist_tx(const factory_instance_t *fi,
                                    uint8_t **out);

/* Deserialize signed distribution TX into factory instance */
bool ss_persist_deserialize_dist_tx(factory_instance_t *fi,
                                    const uint8_t *data, size_t len);

/* --- Tier B: PS leaf double-spend defense ---
 *
 * Mirrors upstream's client_ps_signed_inputs persist table (SuperScalar
 * persist.c schema v20, see /docs/pseudo-spilman.md). For every PS leaf
 * advance the client co-signs, we record (parent_txid, vout) -> sighash
 * so a second-sign attempt against the same parent UTXO with a DIFFERENT
 * sighash is detected and refused. This is the SOLE security property
 * protecting PS leaves — DW leaves use decrementing nSequence instead and
 * don't need this.
 *
 * Key layout:
 *   superscalar/factories/{iid_hex}/ps_signed_inputs/{parent_txid_hex}
 *
 * Entry value layout:
 *   u32 BE          parent_vout
 *   u8[32]          sighash (BIP-341 key-path, SIGHASH_DEFAULT)
 */
void ss_persist_key_ps_signed_input(const factory_instance_t *fi,
				    const uint8_t parent_txid[32],
				    char *out, size_t len);

size_t ss_persist_serialize_ps_signed_input(uint32_t parent_vout,
					    const uint8_t sighash[32],
					    uint8_t **out);

bool ss_persist_deserialize_ps_signed_input(const uint8_t *data, size_t len,
					    uint32_t *parent_vout_out,
					    uint8_t sighash_out[32]);

#endif /* SUPERSCALAR_PERSIST_H */
