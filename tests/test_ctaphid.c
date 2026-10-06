#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ctaphid.h"
static uint8_t frames[128][64];static unsigned nframes;static uint32_t rng=0x12345678;
static void emit(const uint8_t f[64],void *ctx){(void)ctx;assert(nframes<128);memcpy(frames[nframes++],f,64);}
static uint32_t rnd(void *ctx){(void)ctx;return ++rng;}
bool fido_is_preflight(const uint8_t *in, size_t n) {
    (void)in;
    (void)n;
    return false;
}
void fido_execute(const uint8_t *in,size_t n,bool touch_confirmed,uint8_t *out,size_t *olen){
    (void)n;(void)touch_confirmed;out[0]=in[0]==4?0:0x12;*olen=1;
}
int main(void){
    ctaphid_t h;ctaphid_init(&h,emit,rnd,NULL);
    uint8_t init[64]={0xff,0xff,0xff,0xff,0x86,0,8,1,2,3,4,5,6,7,8};
    ctaphid_receive(&h,init,100);assert(nframes==1&&frames[0][4]==0x86);
    uint8_t cid[4];memcpy(cid,frames[0]+15,4);
    uint8_t f[64]={0};memcpy(f,cid,4);f[4]=0x90;f[6]=1;f[7]=4;
    nframes=0;ctaphid_receive(&h,f,200);
    assert(nframes==1&&frames[0][4]==0x90&&frames[0][7]==0);
    f[7]=1;nframes=0;ctaphid_receive(&h,f,300);
    assert(h.waiting_for_touch&&nframes==0);
    ctaphid_tick(&h,410);assert(nframes==1&&frames[0][4]==0xbb&&frames[0][7]==2);
    ctaphid_touch(&h,450);assert(!h.waiting_for_touch&&nframes==2&&frames[1][4]==0x90);
    nframes=0;ctaphid_receive(&h,f,600);assert(h.waiting_for_touch);
    f[4]=0x91;f[6]=0;ctaphid_receive(&h,f,610);assert(!h.waiting_for_touch);
    nframes=0;f[4]=0x90;f[6]=1;f[7]=2;ctaphid_receive(&h,f,800);
    ctaphid_tick(&h,30900);assert(!h.waiting_for_touch&&nframes>0);
    assert(frames[nframes-1][7]==0x2f);
    puts("PASS: CTAPHID INIT, CBOR, keepalive, touch, cancel, timeout");
}

/* Mock seed state for CTAPHID-only tests. */
bool fc_is_unlocked(void){return true;}
