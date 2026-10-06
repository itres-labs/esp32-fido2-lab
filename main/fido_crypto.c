/* LAB-ONLY: PIN-derived AES-GCM wrapping of the credential root; no device key. */
#include "fido_crypto.h"
#include <string.h>
#include <limits.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_random.h"
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"

/* PBKDF2 iterations deliberately versioned in the blob. Benchmark on actual
 * ESP32-S3, do not claim resistance to offline guessing of weak passphrases. */
#define ROOT_WRAP_ITERATIONS 40000u
#define ROOT_RECORD_VERSION 1u
#define ROOT_NS "fido_lab"
#define ROOT_KEY "root_enc_v1"
typedef struct {
    uint8_t version;
    uint8_t salt[16];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t ciphertext[32];
} wrapped_root_t;
static uint8_t root[32];
static bool unlocked=false, configured=false;
void fc_random(uint8_t *data,size_t n){esp_fill_random(data,n);}
static bool hmac(const uint8_t *data,size_t len,uint8_t output[32]){
    const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return unlocked && md && mbedtls_md_hmac(md,root,sizeof(root),data,len,output)==0;
}
bool fc_sha256(const uint8_t *data,size_t n,uint8_t out[32]){
    const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return md && mbedtls_md(md,data,n,out)==0;
}
static bool make_aes_key(const uint8_t pin_hash[16], const uint8_t salt[16], uint8_t key[32]) {
    return mbedtls_pkcs5_pbkdf2_hmac_ext(
        MBEDTLS_MD_SHA256, pin_hash, 16, salt, 16,
        ROOT_WRAP_ITERATIONS, 32, key) == 0;
}
static bool wrap_root(const uint8_t pin_hash[16], const uint8_t secret[32], wrapped_root_t *rec) {
    uint8_t key[32]={0};
    rec->version=ROOT_RECORD_VERSION;
    fc_random(rec->salt,sizeof(rec->salt));
    fc_random(rec->iv,sizeof(rec->iv));
    bool ok=make_aes_key(pin_hash,rec->salt,key);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if(ok)ok=mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,256)==0;
    if(ok)ok=mbedtls_gcm_crypt_and_tag(&gcm,MBEDTLS_GCM_ENCRYPT,32,
            rec->iv,sizeof(rec->iv),NULL,0,secret,rec->ciphertext,sizeof(rec->tag),rec->tag)==0;
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key,sizeof(key));
    return ok;
}
static bool unwrap_root(const uint8_t pin_hash[16], const wrapped_root_t *rec, uint8_t secret[32]) {
    if(rec->version!=ROOT_RECORD_VERSION)return false;
    uint8_t key[32]={0};
    bool ok=make_aes_key(pin_hash,rec->salt,key);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if(ok)ok=mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,256)==0;
    if(ok)ok=mbedtls_gcm_auth_decrypt(&gcm,32,rec->iv,sizeof(rec->iv),NULL,0,
                                      rec->tag,sizeof(rec->tag),rec->ciphertext,secret)==0;
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key,sizeof(key));
    if(!ok)mbedtls_platform_zeroize(secret,32);
    return ok;
}
static bool load_record(wrapped_root_t *rec) {
    nvs_handle_t h;
    if(nvs_open(ROOT_NS,NVS_READONLY,&h)!=ESP_OK)return false;
    size_t n=sizeof(*rec);
    esp_err_t e=nvs_get_blob(h,ROOT_KEY,rec,&n);
    nvs_close(h);
    return e==ESP_OK && n==sizeof(*rec) && rec->version==ROOT_RECORD_VERSION;
}
static bool save_record(const wrapped_root_t *rec,bool initialize_counter) {
    nvs_handle_t h;
    if(nvs_open(ROOT_NS,NVS_READWRITE,&h)!=ESP_OK)return false;
    esp_err_t e=nvs_set_blob(h,ROOT_KEY,rec,sizeof(*rec));
    if(e==ESP_OK && initialize_counter)e=nvs_set_u32(h,"counter",0);
    if(e==ESP_OK && initialize_counter)e=nvs_set_u8(h,"pin_retries",8);
    if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);
    return e==ESP_OK;
}
bool fc_init(void) {
    unlocked=false; configured=false;
    mbedtls_platform_zeroize(root,sizeof(root));
    if(nvs_flash_init()!=ESP_OK)return false; /* never auto-erase */
    nvs_handle_t h;
    if(nvs_open(ROOT_NS,NVS_READWRITE,&h)!=ESP_OK)return false;
    /* FAIL CLOSED on an old plaintext root. Explicit erase-flash is required. */
    size_t legacy_size=0;
    esp_err_t e=nvs_get_blob(h,"root_v1",NULL,&legacy_size);
    nvs_close(h);
    if(e==ESP_OK || (e!=ESP_ERR_NVS_NOT_FOUND))return false;
    wrapped_root_t rec;
    configured=load_record(&rec);
    if(!configured){
        /* Fresh flash is legitimate, but never overwrite malformed encrypted data. */
        nvs_handle_t chk;
        if(nvs_open(ROOT_NS,NVS_READONLY,&chk)==ESP_OK){
            size_t size=0;
            e=nvs_get_blob(chk,ROOT_KEY,NULL,&size);
            nvs_close(chk);
            if(e!=ESP_ERR_NVS_NOT_FOUND)return false;
        }
    }
    mbedtls_platform_zeroize(&rec,sizeof(rec));
    return true;
}
bool fc_is_configured(void){return configured;}
bool fc_is_unlocked(void){return unlocked;}
void fc_lock(void){mbedtls_platform_zeroize(root,sizeof(root));unlocked=false;}
bool fc_set_passphrase_hash(const uint8_t pin_hash[16]) {
    if(configured)return false;
    uint8_t fresh[32]={0},verified[32]={0};wrapped_root_t rec={0};
    fc_random(fresh,sizeof(fresh));
    bool ok=wrap_root(pin_hash,fresh,&rec) && unwrap_root(pin_hash,&rec,verified);
    uint8_t diff=0;
    for(size_t i=0;i<sizeof(fresh);i++)diff|=fresh[i]^verified[i];
    if(diff)ok=false;
    if(ok)ok=save_record(&rec,true);
    mbedtls_platform_zeroize(verified,sizeof(verified));
    mbedtls_platform_zeroize(fresh,sizeof(fresh));
    mbedtls_platform_zeroize(&rec,sizeof(rec));
    if(ok)configured=true;
    return ok;
}
bool fc_unlock_hash(const uint8_t pin_hash[16]) {
    fc_lock();
    if(!configured)return false;
    wrapped_root_t rec={0};uint8_t recovered[32]={0};
    bool ok=load_record(&rec) && unwrap_root(pin_hash,&rec,recovered);
    if(ok){memcpy(root,recovered,sizeof(root));unlocked=true;}
    mbedtls_platform_zeroize(&rec,sizeof(rec));
    mbedtls_platform_zeroize(recovered,sizeof(recovered));
    return ok;
}
bool fc_change_passphrase_hash(const uint8_t old_hash[16],const uint8_t new_hash[16]) {
    wrapped_root_t oldrec={0},newrec={0};uint8_t tmp[32]={0},verified[32]={0};
    bool ok=configured && load_record(&oldrec) && unwrap_root(old_hash,&oldrec,tmp);
    if(ok)ok=wrap_root(new_hash,tmp,&newrec) && unwrap_root(new_hash,&newrec,verified);
    uint8_t diff=0;
    for(size_t i=0;i<sizeof(tmp);i++)diff|=tmp[i]^verified[i];
    if(diff)ok=false;
    if(ok)ok=save_record(&newrec,false);
    mbedtls_platform_zeroize(verified,sizeof(verified));
    /* Any previously-unlocked secret survives in RAM, but an old PIN token
       must be revoked by the caller after a successful PIN change. */
    if(ok){memcpy(root,tmp,sizeof(root));unlocked=true;}
    mbedtls_platform_zeroize(&oldrec,sizeof(oldrec));
    mbedtls_platform_zeroize(&newrec,sizeof(newrec));
    mbedtls_platform_zeroize(tmp,sizeof(tmp));
    return ok;
}
uint8_t fc_pin_retries(void){
    nvs_handle_t h;uint8_t retries=0;
    if(nvs_open(ROOT_NS,NVS_READONLY,&h)!=ESP_OK)return 0;
    if(nvs_get_u8(h,"pin_retries",&retries)!=ESP_OK)retries=0;
    nvs_close(h);return retries;
}
bool fc_pin_set_retries(uint8_t n){
    nvs_handle_t h;if(nvs_open(ROOT_NS,NVS_READWRITE,&h)!=ESP_OK)return false;
    esp_err_t e=nvs_set_u8(h,"pin_retries",n);if(e==ESP_OK)e=nvs_commit(h);
    nvs_close(h);return e==ESP_OK;
}
bool fc_counter_read(uint32_t *c){
    if(!unlocked)return false;
    nvs_handle_t h;if(nvs_open(ROOT_NS,NVS_READONLY,&h)!=ESP_OK)return false;
    esp_err_t e=nvs_get_u32(h,"counter",c);nvs_close(h);return e==ESP_OK;
}
bool fc_counter_increment(uint32_t *c){
    uint32_t n;if(!fc_counter_read(&n)||n==UINT32_MAX)return false;
    nvs_handle_t h;if(nvs_open(ROOT_NS,NVS_READWRITE,&h)!=ESP_OK)return false;
    esp_err_t e=nvs_set_u32(h,"counter",n+1);if(e==ESP_OK)e=nvs_commit(h);nvs_close(h);
    if(e!=ESP_OK)return false;
    *c=n+1;return true;
}
/* v1 IDs had an implicit credProtect policy 1. v2 IDs authenticate the
 * policy together with RP ID and nonce; no separate, mutable NVS policy.
 * Both have an unchanged 33-byte length for existing WebAuthn clients. */
static bool id_tag(uint8_t version,const uint8_t rp[32],
                   const uint8_t nonce[16],uint8_t out[32]){
    uint8_t msg[16+32+16]={0};
    memcpy(msg,version==2 ? "FIDO-ID-V2" : "FIDO-ID-V1",10);
    memcpy(msg+16,rp,32);memcpy(msg+48,nonce,16);
    bool ok=hmac(msg,sizeof(msg),out);
    mbedtls_platform_zeroize(msg,sizeof(msg));
    return ok;
}
bool fc_credential_valid(const uint8_t rp[32],const uint8_t *id,size_t n){
    if(!unlocked || !id || n!=FIDO_ID_LEN ||
       (id[0]!=1 && id[0]!=2) ||
       (id[0]==2 && (id[1]<1 || id[1]>3)))return false;
    uint8_t mac[32]={0};
    if(!id_tag(id[0],rp,id+1,mac))return false;
    uint8_t diff=0;for(int i=0;i<16;i++)diff|=mac[i]^id[17+i];
    mbedtls_platform_zeroize(mac,sizeof(mac));return diff==0;
}
bool fc_credential_policy(const uint8_t rp[32],const uint8_t *id,
                          size_t n,uint8_t *policy){
    if(!policy || !fc_credential_valid(rp,id,n))return false;
    *policy=(id[0]==1) ? 1 : id[1];
    return true;
}
bool fc_credential_new_protected(const uint8_t rp[32],uint8_t policy,
                                 uint8_t id[FIDO_ID_LEN]){
    if(!unlocked || !id || policy<1 || policy>3)return false;
    id[0]=2;
    id[1]=policy;
    fc_random(id+2,15);
    uint8_t mac[32]={0};bool ok=id_tag(2,rp,id+1,mac);
    if(ok)memcpy(id+17,mac,16);
    mbedtls_platform_zeroize(mac,sizeof(mac));return ok;
}
bool fc_credential_new(const uint8_t rp[32],uint8_t id[FIDO_ID_LEN]){
    return fc_credential_new_protected(rp,1,id);
}
static int rng_cb(void *ctx,unsigned char *dst,size_t len){(void)ctx;fc_random(dst,len);return 0;}
static bool derive(const uint8_t rp[32],const uint8_t id[FIDO_ID_LEN],mbedtls_ecp_keypair *key){
    if(!fc_credential_valid(rp,id,FIDO_ID_LEN))return false;
    uint8_t msg[16+32+16+1]={0};
    memcpy(msg,"FIDO-KEY-V1",11);memcpy(msg+16,rp,32);memcpy(msg+48,id+1,16);
    if(mbedtls_ecp_group_load(&key->grp,MBEDTLS_ECP_DP_SECP256R1)!=0)return false;
    uint8_t scalar[32];bool ok=false;
    for(unsigned i=0;i<32;i++){
        msg[64]=(uint8_t)i;
        if(!hmac(msg,sizeof(msg),scalar))break;
        if(mbedtls_mpi_read_binary(&key->d,scalar,32)!=0)break;
        if(mbedtls_mpi_cmp_int(&key->d,0)<=0 || mbedtls_mpi_cmp_mpi(&key->d,&key->grp.N)>=0)continue;
        if(mbedtls_ecp_mul(&key->grp,&key->Q,&key->d,&key->grp.G,rng_cb,NULL)==0)ok=true;
        break;
    }
    mbedtls_platform_zeroize(scalar,sizeof(scalar));
    mbedtls_platform_zeroize(msg,sizeof(msg));
    return ok;
}
bool fc_public_key(const uint8_t rp[32],const uint8_t id[FIDO_ID_LEN],uint8_t x[32],uint8_t y[32]){
    mbedtls_ecp_keypair key;mbedtls_ecp_keypair_init(&key);
    bool ok=derive(rp,id,&key);
    if(ok)ok=mbedtls_mpi_write_binary(&key.Q.X,x,32)==0 && mbedtls_mpi_write_binary(&key.Q.Y,y,32)==0;
    mbedtls_ecp_keypair_free(&key);return ok;
}
bool fc_sign(const uint8_t rp[32],const uint8_t id[FIDO_ID_LEN],const uint8_t hash[32],uint8_t sig[80],size_t *sig_len){
    mbedtls_ecp_keypair key;mbedtls_ecp_keypair_init(&key);
    bool ok=derive(rp,id,&key);
    mbedtls_ecdsa_context ecdsa;mbedtls_ecdsa_init(&ecdsa);
    if(ok)ok=mbedtls_ecdsa_from_keypair(&ecdsa,&key)==0;
    if(ok)ok=mbedtls_ecdsa_write_signature(&ecdsa,MBEDTLS_MD_SHA256,hash,32,sig,80,sig_len,rng_cb,NULL)==0;
    mbedtls_ecdsa_free(&ecdsa);mbedtls_ecp_keypair_free(&key);return ok;
}
