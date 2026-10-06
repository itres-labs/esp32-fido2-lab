#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cbor_min.h"
#include "fido_engine.h"
#include "fido_crypto.h"

/* Protocol-policy test backend only. No production crypto is exercised here. */
static uint32_t ctr;
static uint8_t new_policy;
static bool auth_valid;

bool fc_init(void){return true;}
bool fc_is_configured(void){return true;}
bool fc_is_unlocked(void){return true;}
void fc_random(uint8_t *p,size_t n){memset(p,0x42,n);}
bool fc_sha256(const uint8_t *p,size_t n,uint8_t out[32]){(void)p;(void)n;memset(out,0x33,32);return true;}
void fp_execute(const cb_value *req,uint8_t *out,size_t *n){(void)req;out[0]=0;*n=1;}
bool fp_verify_auth(const uint8_t hash[32],const uint8_t *param,size_t len){
    (void)hash;(void)param;return auth_valid && len==16;
}
bool fc_credential_new_protected(const uint8_t rp[32],uint8_t policy,uint8_t id[33]){
    (void)rp;new_policy=policy;memset(id,0x42,33);id[0]=2;id[1]=policy;return policy>=1&&policy<=3;
}
bool fc_credential_new(const uint8_t rp[32],uint8_t id[33]){return fc_credential_new_protected(rp,1,id);}
bool fc_credential_valid(const uint8_t rp[32],const uint8_t *id,size_t n){
    (void)rp;return n==33 && id[0]==2 && id[1]>=1 && id[1]<=3;
}
bool fc_credential_policy(const uint8_t rp[32],const uint8_t *id,size_t n,uint8_t *policy){
    (void)rp;if(!policy || !fc_credential_valid(rp,id,n))return false;*policy=id[1];return true;
}
bool fc_public_key(const uint8_t rp[32],const uint8_t id[33],uint8_t x[32],uint8_t y[32]){
    (void)rp;(void)id;memset(x,0x11,32);memset(y,0x22,32);return true;
}
bool fc_sign(const uint8_t rp[32],const uint8_t id[33],const uint8_t hash[32],uint8_t sig[80],size_t *n){
    (void)rp;(void)id;(void)hash;sig[0]=0x30;sig[1]=0;*n=2;return true;
}
bool fc_counter_read(uint32_t *c){*c=ctr;return true;}
bool fc_counter_increment(uint32_t *c){*c=++ctr;return true;}

static void make_policy3(uint8_t msg[1024],size_t *n){
    cb_writer w;cb_init(&w,msg+1,1023);msg[0]=1;
    cb_head(&w,5,6);
    cb_int(&w,1);uint8_t hash[32]={0};cb_bstr(&w,hash,32);
    cb_int(&w,2);cb_head(&w,5,1);cb_tstr(&w,"id");cb_tstr(&w,"localhost");
    cb_int(&w,3);cb_head(&w,5,1);cb_tstr(&w,"id");cb_bstr(&w,(const uint8_t*)"u",1);
    cb_int(&w,4);cb_head(&w,4,1);cb_head(&w,5,2);
      cb_tstr(&w,"type");cb_tstr(&w,"public-key");
      cb_tstr(&w,"alg");cb_int(&w,-7);
    cb_int(&w,6);cb_head(&w,5,1);cb_tstr(&w,"credProtect");cb_int(&w,3);
    cb_int(&w,7);cb_head(&w,5,1);cb_tstr(&w,"rk");cb_head(&w,7,20);
    assert(w.ok);*n=w.n+1;
}

static void get_policy3(uint8_t msg[1024],size_t *n,bool with_uv){
    cb_writer w;cb_init(&w,msg+1,1023);msg[0]=2;
    cb_head(&w,5,with_uv?5:3);
    cb_int(&w,1);cb_tstr(&w,"localhost");
    cb_int(&w,2);uint8_t hash[32]={0};cb_bstr(&w,hash,32);
    cb_int(&w,3);cb_head(&w,4,1);cb_head(&w,5,2);
      cb_tstr(&w,"type");cb_tstr(&w,"public-key");
      cb_tstr(&w,"id");uint8_t id[33];memset(id,0x42,sizeof(id));id[0]=2;id[1]=3;cb_bstr(&w,id,sizeof(id));
    if(with_uv){
        uint8_t auth[16]={0xaa};
        cb_int(&w,6);cb_bstr(&w,auth,sizeof(auth));
        cb_int(&w,7);cb_int(&w,1);
    }
    assert(w.ok);*n=w.n+1;
}

int main(void){
    uint8_t msg[1024],out[1024];size_t n=0,len=0;

    /* Regression for the deterministic-CBOR bug: getInfo must start at key 1,
       not extension key 2. It must also advertise credProtect. */
    msg[0]=4;fido_execute(msg,1,false,out,&len);
    assert(out[0]==0 && len>4 && out[1]==0xa9 && out[2]==0x01);
    cb_value info,exts,ext;assert(cb_decode(out+1,len-1,&info));
    assert(cb_map_int(&info,2,&exts) && exts.type==4 && exts.arg==1);
    assert(cb_array_at(&exts,0,&ext) && ext.type==3 && ext.arg==11 && memcmp(ext.p,"credProtect",11)==0);

    make_policy3(msg,&n);fido_execute(msg,n,true,out,&len);
    assert(out[0]==0 && new_policy==3);
    cb_value resp,authdata;assert(cb_decode(out+1,len-1,&resp));
    assert(cb_map_int(&resp,2,&authdata) && authdata.type==2 && authdata.arg>37);
    assert((authdata.p[32] & 0x80)==0x80); /* ED bit set when extension output exists. */

    get_policy3(msg,&n,false);auth_valid=false;fido_execute(msg,n,true,out,&len);
    assert(out[0]==0x36); /* PIN_REQUIRED: unlocked RAM alone cannot satisfy policy 3. */

    get_policy3(msg,&n,true);auth_valid=true;fido_execute(msg,n,true,out,&len);
    assert(out[0]==0);
    assert(cb_decode(out+1,len-1,&resp));
    assert(cb_map_int(&resp,2,&authdata) && authdata.type==2 && authdata.arg==37);
    assert((authdata.p[32] & 0x05)==0x05); /* UP + UV */

    puts("PASS: getInfo credProtect ordering/advertisement and policy-3 per-request UV enforcement");
    return 0;
}
