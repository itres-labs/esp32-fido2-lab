#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cbor_min.h"
#include "fido_engine.h"
#include "fido_crypto.h"
/* Mock backend ONLY for testing parser/encoding, NOT for firmware. */
static uint32_t ctr;
static bool simulated_unlocked=true;
static unsigned signs;
static uint8_t last_signed_up;
bool fc_init(void){return true;}
bool fc_is_configured(void){return true;}
bool fc_is_unlocked(void){return simulated_unlocked;}
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
bool fc_sign(const uint8_t rp[32],const uint8_t id[33],const uint8_t hash[32],uint8_t sig[80],size_t *n){
    (void)rp;(void)id;(void)hash;signs++;sig[0]=0x30;sig[1]=0;*n=2;return true;
}
bool fc_counter_read(uint32_t *c){*c=ctr;return true;}
bool fc_counter_increment(uint32_t *c){*c=++ctr;return true;}
static void request_make(uint8_t *msg,size_t *n,bool rk){
    cb_writer w;cb_init(&w,msg+1,1023);msg[0]=1;
    cb_head(&w,5,5);
    cb_int(&w,1);uint8_t hash[32]={0};cb_bstr(&w,hash,32);
    cb_int(&w,2);cb_head(&w,5,1);cb_tstr(&w,"id");cb_tstr(&w,"localhost");
    cb_int(&w,3);cb_head(&w,5,1);cb_tstr(&w,"id");cb_bstr(&w,(uint8_t*)"1",1);
    cb_int(&w,4);cb_head(&w,4,1);cb_head(&w,5,2);
       cb_tstr(&w,"type");cb_tstr(&w,"public-key");
       cb_tstr(&w,"alg");cb_int(&w,-7);
    cb_int(&w,7);cb_head(&w,5,1);cb_tstr(&w,"rk");cb_head(&w,7,rk?21:20);
    assert(w.ok);*n=w.n+1;
}
static void request_get(uint8_t *msg,size_t *n,bool wrong_id,bool probe){
    cb_writer w;cb_init(&w,msg+1,1023);msg[0]=2;
    cb_head(&w,5,probe?4:3);
    cb_int(&w,1);cb_tstr(&w,"localhost");
    cb_int(&w,2);uint8_t hash[32]={0};cb_bstr(&w,hash,32);
    cb_int(&w,3);cb_head(&w,4,1);cb_head(&w,5,2);
       cb_tstr(&w,"type");cb_tstr(&w,"public-key");
       cb_tstr(&w,"id");uint8_t id[33];memset(id,0x42,33);id[0]=wrong_id?2:1;cb_bstr(&w,id,33);
    if(probe){cb_int(&w,5);cb_head(&w,5,1);cb_tstr(&w,"up");cb_head(&w,7,20);}
    assert(w.ok);*n=w.n+1;
}
int main(void){
    uint8_t msg[1024],out[1024];size_t n,len;
    msg[0]=4;fido_execute(msg,1,false,out,&len);assert(out[0]==0&&len>20);
    cb_value v,info;assert(cb_decode(out+1,len-1,&v) && cb_map_int(&v,1,&info));
    /* Chromium rejects a GetInfo that advertises clientPin=false without
     * pinUvAuthProtocols: false means supported-but-unconfigured, NOT absent. */
    cb_value opts, flag;
    assert(cb_map_int(&v,4,&opts));
    assert(cb_map_text(&opts,"clientPin",&flag) && flag.type==7 && flag.arg==21);
    assert(cb_map_int(&v,6,&flag) && flag.type==4 && flag.arg==1);
    assert(cb_map_text(&opts,"up",&flag) && flag.type==7 && flag.arg==21);
    assert(cb_map_text(&opts,"rk",&flag) && flag.type==7 && flag.arg==20);
    request_make(msg,&n,true);fido_execute(msg,n,false,out,&len);assert(out[0]==0x2b);
    simulated_unlocked=false;
    request_make(msg,&n,false);fido_execute(msg,n,true,out,&len);assert(out[0]==0x36);
    request_get(msg,&n,false,true);fido_execute(msg,n,false,out,&len);assert(out[0]==0x36);
    simulated_unlocked=true;
    request_make(msg,&n,false);fido_execute(msg,n,false,out,&len);assert(out[0]==0x3b);
    assert(signs==0&&ctr==0); /* never register without touch */
    fido_execute(msg,n,true,out,&len);assert(out[0]==0);
    assert(cb_decode(out+1,len-1,&v));cb_value fmt,auth;
    assert(cb_map_int(&v,1,&fmt)&&fmt.type==3&&fmt.arg==4&&memcmp(fmt.p,"none",4)==0);
    assert(cb_map_int(&v,2,&auth)&&auth.type==2&&auth.arg>100&&auth.p[32]==0x41);
    assert(auth.p[37+16]==0&&auth.p[37+17]==33);
    request_get(msg,&n,true,false);fido_execute(msg,n,false,out,&len);assert(out[0]==0x2e);
    request_get(msg,&n,false,false);fido_execute(msg,n,false,out,&len);assert(out[0]==0x3b);
    assert(signs==0&&ctr==0); /* host cannot set UP=1 */
    fido_execute(msg,n,true,out,&len);assert(out[0]==0);
    assert(cb_decode(out+1,len-1,&v)&&cb_map_int(&v,2,&auth)&&auth.type==2&&auth.arg==37);
    assert(auth.p[32]==1&&auth.p[36]==1&&last_signed_up==1&&signs==1);
    uint32_t before = ctr;
    request_get(msg,&n,false,true);
    assert(fido_is_preflight(msg,n));
    fido_execute(msg,n,false,out,&len);
    assert(out[0]==0 && ctr==before && signs==2); /* real silent signature */
    assert(cb_decode(out+1,len-1,&v) && cb_map_int(&v,2,&auth));
    assert(auth.type==2 && auth.arg==37 && auth.p[32]==0 && auth.p[36]==1);
    assert(last_signed_up==0);
    /* A stale physical touch must not elevate an explicit silent request. */
    fido_execute(msg,n,true,out,&len);
    assert(out[0]==0 && ctr==before && signs==3 && last_signed_up==0);
    request_get(msg,&n,true,true);
    assert(fido_is_preflight(msg,n));
    fido_execute(msg,n,false,out,&len);
    assert(out[0]==0x2e && len==1 && ctr==before && signs==3); /* unknown ID */
    request_get(msg,&n,false,false);
    assert(!fido_is_preflight(msg,n));
    msg[0]=1;msg[1]=0xff;fido_execute(msg,2,false,out,&len);assert(out[0]==0x12);
    puts("PASS: getInfo, registration touch gating, normal assertion touch gating, silent UP=0 signed, unchanged counter, invalid ID, malformed CBOR");
}
