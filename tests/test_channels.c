#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ctaphid.h"
static uint8_t last[64];
static uint32_t seed = 100;
static void emit(const uint8_t *frame, void *x) { (void)x; memcpy(last, frame, 64); }
static uint32_t rnd(void *x) { (void)x; return ++seed; }
bool fido_is_preflight(const uint8_t *in, size_t n) {
    (void)in;
    (void)n;
    return false;
}
void fido_execute(const uint8_t *in, size_t n, bool touch_confirmed, uint8_t *out, size_t *olen) {
    (void)in; (void)n; (void)touch_confirmed; out[0] = 0; *olen = 1;
}
static uint32_t be32(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}
static uint32_t init(ctaphid_t *h, uint32_t ms) {
    uint8_t p[64] = {0xff, 0xff, 0xff, 0xff, 0x86, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    ctaphid_receive(h, p, ms);
    assert(last[4] == 0x86);
    return be32(last + 15);
}
static uint8_t ping(ctaphid_t *h, uint32_t cid, uint32_t ms) {
    uint8_t p[64] = {0};
    p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
    p[4] = 0x81; p[5] = 0; p[6] = 1; p[7] = 0x5a;
    ctaphid_receive(h, p, ms);
    return last[4];
}
int main(void) {
    ctaphid_t h;
    ctaphid_init(&h, emit, rnd, NULL);
    uint32_t c[CTAPHID_MAX_CHANNELS];
    for (int i = 0; i < CTAPHID_MAX_CHANNELS; ++i)
        c[i] = init(&h, 100 + i * 10);
    assert(ping(&h, c[0], 300) == 0x81); /* oldest CID is now recently used */
    uint32_t newcomer = init(&h, 400);
    assert(newcomer != 0);
    assert(ping(&h, c[0], 410) == 0x81); /* live older CID survives */
    assert(ping(&h, c[1], 420) == 0xbf && last[7] == 0x0b); /* stale CID evicted */
    /* A new channel can still be allocated after many successive clients. */
    for (int i = 0; i < 100; ++i) (void)init(&h, 1000 + i * 10);
    puts("PASS: 117 INITs, CID recycling, keep recently used CID, stale invalidation");
}

/* Mock seed state for CTAPHID-only tests. */
bool fc_is_unlocked(void){return true;}
