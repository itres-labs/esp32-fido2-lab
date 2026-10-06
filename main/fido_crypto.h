#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define FIDO_ID_LEN 33
bool fc_init(void);
bool fc_is_configured(void);
bool fc_is_unlocked(void);
void fc_lock(void);
bool fc_set_passphrase_hash(const uint8_t pin_hash[16]);
bool fc_unlock_hash(const uint8_t pin_hash[16]);
bool fc_change_passphrase_hash(const uint8_t old_hash[16],const uint8_t new_hash[16]);
uint8_t fc_pin_retries(void);
bool fc_pin_set_retries(uint8_t n);
bool fc_sha256(const uint8_t *data,size_t n,uint8_t out[32]);
void fc_random(uint8_t *data,size_t n);
bool fc_credential_new(const uint8_t rp_hash[32],uint8_t id[FIDO_ID_LEN]);
bool fc_credential_new_protected(const uint8_t rp_hash[32],uint8_t policy,uint8_t id[FIDO_ID_LEN]);
bool fc_credential_policy(const uint8_t rp_hash[32],const uint8_t *id,size_t n,uint8_t *policy);
bool fc_credential_valid(const uint8_t rp_hash[32],const uint8_t *id,size_t n);
bool fc_public_key(const uint8_t rp_hash[32],const uint8_t id[FIDO_ID_LEN],uint8_t x[32],uint8_t y[32]);
bool fc_sign(const uint8_t rp_hash[32],const uint8_t id[FIDO_ID_LEN],const uint8_t msg_hash[32],uint8_t sig[80],size_t *sig_len);
bool fc_counter_read(uint32_t *c);
bool fc_counter_increment(uint32_t *c);
