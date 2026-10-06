#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CTAPHID_FRAME_SIZE 64
#define CTAPHID_MAX_MSG 1024
#define CTAPHID_MAX_CHANNELS 16
#define CTAPHID_BROADCAST 0xffffffffu

typedef void (*ctaphid_emit_t)(const uint8_t frame[CTAPHID_FRAME_SIZE], void *ctx);
typedef uint32_t (*ctaphid_random_t)(void *ctx);

typedef struct {
    uint32_t channels[CTAPHID_MAX_CHANNELS];
    uint32_t channel_last_seen_ms[CTAPHID_MAX_CHANNELS];
    uint32_t active_cid;
    uint32_t started_ms;
    uint32_t last_keepalive_ms;
    bool waiting_for_touch;
    uint16_t expected;
    uint16_t received;
    uint8_t next_seq;
    uint8_t pending_cmd;
    uint8_t buffer[CTAPHID_MAX_MSG];
    ctaphid_emit_t emit;
    ctaphid_random_t random;
    void *ctx;
} ctaphid_t;

void ctaphid_init(ctaphid_t *h, ctaphid_emit_t emit, ctaphid_random_t rnd, void *ctx);
void ctaphid_receive(ctaphid_t *h, const uint8_t packet[CTAPHID_FRAME_SIZE], uint32_t ms);
void ctaphid_tick(ctaphid_t *h, uint32_t ms);

/* Fresh button press after request; never pre-authorizes operations. */
void ctaphid_touch(ctaphid_t *h, uint32_t ms);
