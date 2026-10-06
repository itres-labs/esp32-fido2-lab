#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "cbor_min.h"
/* CTAP2.0 authenticatorClientPIN protocol 1, EXPERIMENTAL / LAB ONLY. */
void fp_init(void);
void fp_execute(const cb_value *req, uint8_t out[1024],size_t *olen);
bool fp_verify_auth(const uint8_t client_data_hash[32],const uint8_t *param,size_t len);
