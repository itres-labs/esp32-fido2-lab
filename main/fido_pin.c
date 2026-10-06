/* CTAP 2.0 clientPIN protocol 1. LAB-ONLY. No flash/eFuse-stored AES key. */
#include "fido_pin.h"
#include "fido_crypto.h"
#include <string.h>
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/ecp.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#define FP_OK 0x00
#define FP_ERR_CBOR 0x12
#define FP_MISSING 0x14
#define FP_PIN_INVALID 0x31
#define FP_PIN_BLOCKED 0x32
#define FP_PIN_AUTH_INVALID 0x33
#define FP_PIN_AUTH_BLOCKED 0x34
#define FP_PIN_NOT_SET 0x35
#define FP_PIN_POLICY 0x37
#define FP_OTHER 0x7f
#define FP_PROTOCOL 0x2b

static mbedtls_ecp_keypair ephemeral;
static bool ephemeral_valid=false, token_issued=false;
static uint8_t token[32];
static unsigned failed_since_power_on=0;

static void error(uint8_t *out,size_t *olen,uint8_t code){out[0]=code;*olen=1;}
static int rng(void *c, unsigned char *data,size_t n){(void)c;fc_random(data,n);return 0;}
static void clear_ephemeral(void){mbedtls_ecp_keypair_free(&ephemeral);mbedtls_ecp_keypair_init(&ephemeral);ephemeral_valid=false;}
void fp_init(void){
    mbedtls_ecp_keypair_init(&ephemeral);
    ephemeral_valid=false;token_issued=false;failed_since_power_on=0;
    fc_random(token,sizeof(token));
}
static bool hmac_bytes(const uint8_t *key,size_t key_len,const uint8_t *data,size_t n,uint8_t output[32]){
    const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return md && mbedtls_md_hmac(md,key,key_len,data,n,output)==0;
}
static bool constant_time_eq(const uint8_t *a,const uint8_t *b,size_t n){
    uint8_t diff=0;for(size_t i=0;i<n;i++)diff|=a[i]^b[i];return diff==0;
}
static bool new_key_agreement(void){
    clear_ephemeral();
    if(mbedtls_ecp_group_load(&ephemeral.grp,MBEDTLS_ECP_DP_SECP256R1)!=0)return false;
    if(mbedtls_ecp_gen_privkey(&ephemeral.grp,&ephemeral.d,rng,NULL)!=0)return false;
    if(mbedtls_ecp_mul(&ephemeral.grp,&ephemeral.Q,&ephemeral.d,&ephemeral.grp.G,rng,NULL)!=0)return false;
    ephemeral_valid=true;return true;
}
static bool shared_secret(const cb_value *platform_key,uint8_t secret[32]){
    if(!ephemeral_valid || platform_key->type!=5)return false;
    cb_value val;int64_t n;
    const uint8_t *x,*y;size_t nx,ny;
    if(!cb_map_int(platform_key,1,&val)||!cb_integer(&val,&n)||n!=2)return false;
    if(!cb_map_int(platform_key,3,&val)||!cb_integer(&val,&n)||n!=-25)return false;
    if(!cb_map_int(platform_key,-1,&val)||!cb_integer(&val,&n)||n!=1)return false;
    if(!cb_map_int(platform_key,-2,&val)||!cb_bytes(&val,&x,&nx)||nx!=32)return false;
    if(!cb_map_int(platform_key,-3,&val)||!cb_bytes(&val,&y,&ny)||ny!=32)return false;
    mbedtls_ecp_point pub,point;
    mbedtls_ecp_point_init(&pub);mbedtls_ecp_point_init(&point);
    uint8_t raw[32]={0};
    bool ok=mbedtls_mpi_read_binary(&pub.X,x,32)==0 &&
            mbedtls_mpi_read_binary(&pub.Y,y,32)==0 &&
            mbedtls_mpi_lset(&pub.Z,1)==0 &&
            mbedtls_ecp_check_pubkey(&ephemeral.grp,&pub)==0 &&
            mbedtls_ecp_mul(&ephemeral.grp,&point,&ephemeral.d,&pub,rng,NULL)==0 &&
            mbedtls_mpi_write_binary(&point.X,raw,32)==0 &&
            fc_sha256(raw,sizeof(raw),secret);
    mbedtls_platform_zeroize(raw,sizeof(raw));
    mbedtls_ecp_point_free(&pub);mbedtls_ecp_point_free(&point);
    return ok;
}
static bool aes_cbc(const uint8_t secret[32],const uint8_t *src,uint8_t *dst,size_t n,bool encrypt){
    if(!n || n%16)return false;
    uint8_t iv[16]={0};mbedtls_aes_context aes;mbedtls_aes_init(&aes);
    int e=encrypt?mbedtls_aes_setkey_enc(&aes,secret,256):mbedtls_aes_setkey_dec(&aes,secret,256);
    if(e==0)e=mbedtls_aes_crypt_cbc(&aes,encrypt?MBEDTLS_AES_ENCRYPT:MBEDTLS_AES_DECRYPT,n,iv,src,dst);
    mbedtls_aes_free(&aes);mbedtls_platform_zeroize(iv,sizeof(iv));
    return e==0;
}
static bool pin_utf8_length(const uint8_t pin[64],size_t *length){
    size_t n=0;
    while(n<64 && pin[n])n++;
    if(n<12 || n>63)return false;  /* Passphrase policy: >=12 bytes in lab. */
    for(size_t i=n;i<64;i++)if(pin[i])return false;
    /* Reject invalid UTF-8 and overlong codepoints before provisioning. */
    for(size_t i=0;i<n;){
        uint8_t v=pin[i];size_t width=0;
        if(v<0x80)width=1;
        else if(v>=0xc2 && v<=0xdf)width=2;
        else if(v>=0xe0 && v<=0xef)width=3;
        else if(v>=0xf0 && v<=0xf4)width=4;
        else return false;
        if(i+width>n)return false;
        for(size_t j=1;j<width;j++)if((pin[i+j]&0xc0)!=0x80)return false;
        if(width==3 && ((v==0xe0 && pin[i+1]<0xa0)||(v==0xed && pin[i+1]>=0xa0)))return false;
        if(width==4 && ((v==0xf0 && pin[i+1]<0x90)||(v==0xf4 && pin[i+1]>=0x90)))return false;
        i+=width;
    }
    *length=n;return true;
}
static void reset_pin_token(void){fc_random(token,sizeof(token));token_issued=false;}
bool fp_verify_auth(const uint8_t hash[32],const uint8_t *param,size_t len){
    uint8_t mac[32]={0};
    bool ok=token_issued && len==16 && hmac_bytes(token,sizeof(token),hash,32,mac) &&
            constant_time_eq(mac,param,16);
    mbedtls_platform_zeroize(mac,sizeof(mac));
    return ok;
}
static uint8_t bad_pin(void){
    uint8_t tries=fc_pin_retries();
    if(tries>0){tries--;if(!fc_pin_set_retries(tries))return FP_OTHER;}
    failed_since_power_on++;
    if(tries==0)return FP_PIN_BLOCKED;
    if(failed_since_power_on>=3)return FP_PIN_AUTH_BLOCKED;
    return FP_PIN_INVALID;
}
static void pin_response(uint8_t *out,size_t *olen,const uint8_t *data,size_t n,int key){
    cb_writer w;out[0]=0;cb_init(&w,out+1,1023);
    cb_head(&w,5,1);cb_int(&w,key);cb_bstr(&w,data,n);
    if(w.ok)*olen=w.n+1;else error(out,olen,FP_OTHER);
}
void fp_execute(const cb_value *req,uint8_t out[1024],size_t *olen){
    cb_value v;int64_t cmd,protocol;
    error(out,olen,FP_MISSING);
    if(!cb_map_int(req,1,&v)||!cb_integer(&v,&protocol)||protocol!=1){error(out,olen,FP_PROTOCOL);return;}
    if(!cb_map_int(req,2,&v)||!cb_integer(&v,&cmd)){return;}
    if(cmd==1){
        cb_writer w;out[0]=0;cb_init(&w,out+1,1023);
        cb_head(&w,5,1);cb_int(&w,3);cb_int(&w,fc_is_configured()?fc_pin_retries():8);
        if(w.ok)*olen=w.n+1;else error(out,olen,FP_OTHER);
        return;
    }
    if(cmd==2){
        if(!new_key_agreement()){error(out,olen,FP_OTHER);return;}
        uint8_t x[32],y[32];
        if(mbedtls_mpi_write_binary(&ephemeral.Q.X,x,32)!=0 ||
           mbedtls_mpi_write_binary(&ephemeral.Q.Y,y,32)!=0){error(out,olen,FP_OTHER);return;}
        cb_writer w;out[0]=0;cb_init(&w,out+1,1023);
        cb_head(&w,5,1);cb_int(&w,1);cb_head(&w,5,5);
        cb_int(&w,1);cb_int(&w,2);cb_int(&w,3);cb_int(&w,-25);
        cb_int(&w,-1);cb_int(&w,1);
        cb_int(&w,-2);cb_bstr(&w,x,32);
        cb_int(&w,-3);cb_bstr(&w,y,32);
        if(w.ok)*olen=w.n+1;else error(out,olen,FP_OTHER);
        return;
    }
    if(cmd!=3 && cmd!=4 && cmd!=5){error(out,olen,0x01);return;}
    if(cmd==3 && fc_is_configured()){error(out,olen,0x30);return;} /* PIN_ALREADY_SET */
    if(cmd!=3 && !fc_is_configured()){error(out,olen,FP_PIN_NOT_SET);return;}
    if(fc_is_configured() && fc_pin_retries()==0){error(out,olen,FP_PIN_BLOCKED);return;}
    if(failed_since_power_on>=3){error(out,olen,FP_PIN_AUTH_BLOCKED);return;}
    cb_value platform;
    if(!cb_map_int(req,3,&platform)){return;}
    uint8_t shared[32]={0};
    if(!shared_secret(&platform,shared)){error(out,olen,FP_ERR_CBOR);goto finish;}
    cb_value pin_enc,pin_auth,hash_enc;
    const uint8_t *enc=NULL,*auth=NULL,*hash=NULL;size_t enc_n=0,auth_n=0,hash_n=0;
    uint8_t new_pin[64]={0},old_pin_hash[16]={0},new_hash[32]={0},mac[32]={0};
    uint8_t status=FP_OTHER;
    if(cmd==3 || cmd==4){
        if(!cb_map_int(req,4,&pin_auth)||!cb_bytes(&pin_auth,&auth,&auth_n)||auth_n!=16 ||
           !cb_map_int(req,5,&pin_enc)||!cb_bytes(&pin_enc,&enc,&enc_n)||enc_n!=64){
            status=FP_MISSING;goto done;
        }
        /* CHANGE PIN authenticates newPinEnc || pinHashEnc. */
        if(cmd==4){
            if(!cb_map_int(req,6,&hash_enc)||!cb_bytes(&hash_enc,&hash,&hash_n)||hash_n!=16){status=FP_MISSING;goto done;}
            uint8_t concat[80];memcpy(concat,enc,64);memcpy(concat+64,hash,16);
            bool valid=hmac_bytes(shared,sizeof(shared),concat,sizeof(concat),mac);
            mbedtls_platform_zeroize(concat,sizeof(concat));
            if(!valid){status=FP_OTHER;goto done;}
        }else if(!hmac_bytes(shared,sizeof(shared),enc,enc_n,mac)){
            status=FP_OTHER;goto done;
        }
        if(!constant_time_eq(auth,mac,16)){status=FP_PIN_AUTH_INVALID;goto done;}
        if(!aes_cbc(shared,enc,new_pin,64,false)){status=FP_OTHER;goto done;}
        size_t pin_len=0;
        if(!pin_utf8_length(new_pin,&pin_len)){status=FP_PIN_POLICY;goto done;}
        if(!fc_sha256(new_pin,pin_len,new_hash)){status=FP_OTHER;goto done;}
    }
    if(cmd==4 || cmd==5){
        if(cmd==5){
            if(!cb_map_int(req,6,&hash_enc)||!cb_bytes(&hash_enc,&hash,&hash_n)||hash_n!=16){status=FP_MISSING;goto done;}
        }
        if(!aes_cbc(shared,hash,old_pin_hash,16,false)){status=FP_OTHER;goto done;}
        if(!fc_unlock_hash(old_pin_hash)){
            reset_pin_token();
            status=bad_pin();
            goto done;
        }
        failed_since_power_on=0;
        if(!fc_pin_set_retries(8)){status=FP_OTHER;goto done;}
    }
    if(cmd==3){
        if(!fc_set_passphrase_hash(new_hash)){status=FP_OTHER;goto done;}
        /* Protect against using the just-created root until a real PIN token. */
        fc_lock();reset_pin_token();status=FP_OK;
    }else if(cmd==4){
        if(!fc_change_passphrase_hash(old_pin_hash,new_hash)){status=FP_OTHER;goto done;}
        reset_pin_token();fc_lock();status=FP_OK;
    }else{
        uint8_t encrypted[32];
        reset_pin_token();
        if(!aes_cbc(shared,token,encrypted,sizeof(encrypted),true)){status=FP_OTHER;goto done;}
        token_issued=true;
        pin_response(out,olen,encrypted,sizeof(encrypted),2);
        mbedtls_platform_zeroize(encrypted,sizeof(encrypted));
        status=FP_OK;
    }
 done:
    mbedtls_platform_zeroize(new_pin,sizeof(new_pin));
    mbedtls_platform_zeroize(old_pin_hash,sizeof(old_pin_hash));
    mbedtls_platform_zeroize(new_hash,sizeof(new_hash));
    mbedtls_platform_zeroize(mac,sizeof(mac));
    if(status!=FP_OK){
        if(cmd==4 || cmd==5){fc_lock();reset_pin_token();}
        error(out,olen,status);
    }else if(cmd!=5){out[0]=0;*olen=1;}
 finish:
    mbedtls_platform_zeroize(shared,sizeof(shared));
    /* A new getKeyAgreement will generate a new key. */
    clear_ephemeral();
}
