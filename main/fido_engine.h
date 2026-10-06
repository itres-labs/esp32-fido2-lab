#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define FIDO_CBOR_LIMIT 1024
/* Detect getAssertion(options.up=false) for CTAPHID touch routing.
 * This is only a routing hint; fido_execute performs full validation. */
bool fido_is_preflight(const uint8_t *in, size_t in_len);
/* The CTAPHID transport supplies touch_confirmed=true ONLY on a fresh button
 * edge for the current transaction. The engine MUST NOT infer UP from the
 * request itself (an untrusted host controls options.up). */
void fido_execute(const uint8_t *in, size_t in_len, bool touch_confirmed,
                  uint8_t out[FIDO_CBOR_LIMIT], size_t *out_len);
