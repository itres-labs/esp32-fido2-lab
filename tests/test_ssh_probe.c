#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cbor_min.h"
#include "ctaphid.h"
#include "fido_engine.h"
#include "fido_crypto.h"
/* Native mock only: exercise exact USB/CBOR routing and side effects. */
static uint32_t ctr;
static unsigned signs;
static uint8_t last_signed_up;
static uint8_t frames[64][64];
static size_t frame_count;
static uint32_t rng=0x7890;
static void emit(const uint8_t f[64],void *ctx){(void)ctx;assert(frame_count<64);memcpy(frames[frame_count++],f,64);}
static uint32_t rnd(void *ctx){(void)ctx;return ++rng;}
bool fc_init(void){return true;}
bool fc_is_configured(void){return true;}
bool fc_is_unlocked(void){return true;}
void fp_execute(const cb_value *req,uint8_t *out,size_t *n){(void)req;out[0]=0;*n=1;}
bool fp_verify_auth(const uint8_t hash[32],const uint8_t *param,size_t len){
    (void)hash;(void)param;(void)len;return false;
}
void fc_random(uint8_t *p,size_t n){memset(p,0x42,n);}
bool fc_sha256(const uint8_t *p,size_t n,uint8_t out[32]){
    if(n==69)last_signed_up=p[32];
    memset(out,0x33,32);return true;
}
bool fc_credential_new_protected(const uint8_t rp[32],uint8_t policy,uint8_t id[33]){
    (void)rp;memset(id,0x42,33);id[0]=2;id[1]=policy;return policy>=1&&policy<=3;
}
bool fc_credential_new(const uint8_t rp[32],uint8_t id[33]){return fc_credential_new_protected(rp,1,id);}
bool fc_credential_policy(const uint8_t rp[32],const uint8_t *id,size_t n,uint8_t *policy){
    (void)rp;if(!policy||n!=33)return false;*policy=(id[0]==2)?id[1]:1;return id[0]==1||id[0]==2;
}
bool fc_credential_valid(const uint8_t rp[32],const uint8_t *id,size_t n){
    (void)rp;return n==33 && ((id[0]==1 && id[1]==0x42) || (id[0]==2 && id[1]>=1 && id[1]<=3));
}
bool fc_public_key(const uint8_t rp[32],const uint8_t id[33],uint8_t x[32],uint8_t y[32]){(void)rp;(void)id;memset(x,0x11,32);memset(y,0x22,32);return true;}
bool fc_sign(const uint8_t rp[32],const uint8_t id[33],const uint8_t hash[32],uint8_t sig[80],size_t *n){(void)rp;(void)id;(void)hash;signs++;sig[0]=0x30;sig[1]=0;*n=2;return true;}
bool fc_counter_read(uint32_t *c){*c=ctr;return true;}
bool fc_counter_increment(uint32_t *c){*c=++ctr;return true;}
static uint32_t cid;
static void put_cid(uint8_t p[64]){p[0]=cid>>24;p[1]=cid>>16;p[2]=cid>>8;p[3]=(uint8_t)cid;}
static size_t get_req(uint8_t buf[256],bool up, bool known){
    cb_writer w;buf[0]=2;cb_init(&w,buf+1,255);
    cb_head(&w,5,4);
    cb_int(&w,1);cb_tstr(&w,"ssh:");
    cb_int(&w,2);uint8_t hash[32]={0};cb_bstr(&w,hash,32);
    cb_int(&w,3);cb_head(&w,4,1);cb_head(&w,5,2);
    cb_tstr(&w,"type");cb_tstr(&w,"public-key");
    cb_tstr(&w,"id");uint8_t id[33];memset(id,0x42,33);id[0]=known?1:2;cb_bstr(&w,id,33);
    cb_int(&w,5);cb_head(&w,5,1);cb_tstr(&w,"up");cb_head(&w,7,up?21:20);
    assert(w.ok);return w.n+1;
}
static void send(ctaphid_t *h,const uint8_t *msg,size_t len,uint32_t ms){
    uint8_t f[64]={0};put_cid(f);f[4]=0x90;f[5]=(uint8_t)(len>>8);f[6]=(uint8_t)len;
    size_t off=len<57?len:57;memcpy(f+7,msg,off);ctaphid_receive(h,f,ms);
    unsigned seq=0;
    while(off<len){memset(f,0,sizeof(f));put_cid(f);f[4]=seq++;
      size_t n=len-off<59?len-off:59;memcpy(f+5,msg+off,n);
      ctaphid_receive(h,f,ms+seq);off+=n;}
}
static size_t response(uint8_t *dst,size_t cap) {
    assert(frame_count && frames[0][4]==0x90);
    const size_t total=(size_t)frames[0][5]*256+frames[0][6];
    assert(total<=cap);
    size_t off=total<57?total:57;
    memcpy(dst,frames[0]+7,off);
    for(size_t i=1;off<total;i++) {
        assert(i<frame_count && frames[i][4]==i-1);
        const size_t n=total-off<59?total-off:59;
        memcpy(dst+off,frames[i]+5,n);off+=n;
    }
    return total;
}
int main(void){
    ctaphid_t h;ctaphid_init(&h,emit,rnd,NULL);
    uint8_t init[64]={0xff,0xff,0xff,0xff,0x86,0,8,1,2,3,4,5,6,7,8};
    ctaphid_receive(&h,init,100);assert(frame_count==1&&frames[0][4]==0x86);
    cid=(uint32_t)frames[0][15]<<24 | (uint32_t)frames[0][16]<<16 | (uint32_t)frames[0][17]<<8 | frames[0][18];
    uint8_t req[256];size_t len=get_req(req,false,true);
    assert(fido_is_preflight(req,len));frame_count=0;send(&h,req,len,200);
    assert(!h.waiting_for_touch && h.active_cid==0);
    uint8_t resp[1024];size_t resp_n=response(resp,sizeof(resp));
    assert(resp_n>1 && resp[0]==0 && !h.waiting_for_touch);
    cb_value m,auth,signature;
    assert(cb_decode(resp+1,resp_n-1,&m));
    assert(cb_map_int(&m,2,&auth) && auth.type==2 && auth.arg==37);
    assert(auth.p[32]==0 && last_signed_up==0);
    assert(cb_map_int(&m,3,&signature) && signature.type==2 && signature.arg>0);
    assert(ctr==0&&signs==1); /* signed without UP, no NVS wear */
    len=get_req(req,false,false);frame_count=0;send(&h,req,len,300);
    assert(frame_count==1&&frames[0][7]==0x2e&&ctr==0&&signs==1);
    len=get_req(req,true,true);frame_count=0;send(&h,req,len,400);
    assert(h.waiting_for_touch && frame_count==0);
    ctaphid_tick(&h,510);assert(frame_count==1 && frames[0][4]==0xbb);
    frame_count=0;
    ctaphid_touch(&h,600);
    assert(!h.waiting_for_touch&&frame_count>=1&&frames[0][4]==0x90&&frames[0][7]==0);
    resp_n=response(resp,sizeof(resp));assert(resp_n>1);
    assert(cb_decode(resp+1,resp_n-1,&m));
    assert(cb_map_int(&m,2,&auth) && auth.type==2 && auth.arg==37);
    assert(auth.p[32]==1 && last_signed_up==1);
    assert(ctr==1&&signs==2);
    /* No-touch normal assertion must fail with timeout, never sign. */
    frame_count=0;send(&h,req,len,700);assert(h.waiting_for_touch);
    ctaphid_tick(&h,30701);
    assert(frame_count>0 && frames[frame_count-1][4]==0x90 && frames[frame_count-1][7]==0x2f);
    assert(ctr==1&&signs==2);
    puts("PASS: OpenSSH silent UP=0 signed/no NVS write, unknown ID rejected, normal UP=1 requires fresh touch, timeout blocks signing");
}
