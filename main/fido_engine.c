#include "fido_engine.h"
#include "fido_crypto.h"
#include "fido_pin.h"
#include "cbor_min.h"
#include <string.h>
#include <stdbool.h>
#define OK 0x00
#define INVALID_COMMAND 0x01
#define INVALID_PARAMETER 0x02
#define INVALID_CBOR 0x12
#define MISSING_PARAMETER 0x14
#define CREDENTIAL_EXCLUDED 0x19
#define UNSUPPORTED_ALGORITHM 0x26
#define UNSUPPORTED_OPTION 0x2b
#define INVALID_OPTION 0x2c
#define NO_CREDENTIALS 0x2e
#define PIN_NOT_SET 0x35
#define PIN_REQUIRED 0x36
#define PIN_AUTH_INVALID 0x33
#define UP_REQUIRED 0x3b
#define OTHER 0x7f
static const uint8_t aaguid[16]={0}; /* NO FIDO certification / attestation */
static bool integer_key(const cb_value *m,int k,cb_value *out){return cb_map_int(m,k,out);}
static bool text_value(const cb_value *m,const char *name,const uint8_t **str,size_t *n){
    cb_value v;return cb_map_text(m,name,&v) && cb_text(&v,str,n);
}
static void error(uint8_t *out,size_t *n,uint8_t code){out[0]=code;*n=1;}
static bool valid_rp(const uint8_t *s,size_t n){
    if(n==0||n>253)return false;
    /* ASCII RP ID for now (IDNA canonicalisation is the browser's job). */
    for(size_t i=0;i<n;i++)if(s[i]==0 || s[i]>=128 || s[i]=='/' || s[i]==' ' || s[i]=='\\')return false;
    return true;
}
static bool options(const cb_value *map,int key,bool creation,uint8_t *status){
    cb_value v;if(!integer_key(map,key,&v))return true;
    if(v.type!=5){*status=INVALID_CBOR;return false;}
    cb_value flag;bool b;
    if(creation && cb_map_text(&v,"rk",&flag)){
        if(!cb_boolean(&flag,&b)){*status=INVALID_CBOR;return false;}
        if(b){*status=UNSUPPORTED_OPTION;return false;}
    }
    if(cb_map_text(&v,"uv",&flag)){
        if(!cb_boolean(&flag,&b)){*status=INVALID_CBOR;return false;}
        if(b){*status=UNSUPPORTED_OPTION;return false;}
    }
    if(cb_map_text(&v,"up",&flag)){
        if(!cb_boolean(&flag,&b)){*status=INVALID_CBOR;return false;}
        if(creation && !b){*status=INVALID_OPTION;return false;} /* no silent registration */
    }
    return true;
}
static void auth_prefix(uint8_t auth[37],const uint8_t rp_hash[32],uint8_t flags,uint32_t count){
    memcpy(auth,rp_hash,32);auth[32]=flags;
    auth[33]=(uint8_t)(count>>24);auth[34]=(uint8_t)(count>>16);
    auth[35]=(uint8_t)(count>>8);auth[36]=(uint8_t)count;
}
static bool permitted_alg(const cb_value *array){
    if(array->type!=4 || array->arg>32)return false;
    for(size_t i=0;i<array->arg;i++){
        cb_value param,type,alg;int64_t value;
        if(!cb_array_at(array,i,&param)||param.type!=5)continue;
        const uint8_t *name;size_t n;
        if(!cb_map_text(&param,"type",&type)||!cb_text(&type,&name,&n)||n!=10||memcmp(name,"public-key",10))continue;
        if(cb_map_text(&param,"alg",&alg)&&cb_integer(&alg,&value)&&value==-7)return true;
    }
    return false;
}
static bool descriptor_id(const cb_value *desc,const uint8_t **p,size_t *n){
    if(desc->type!=5)return false;
    cb_value id,type;const uint8_t *str;size_t slen;
    return cb_map_text(desc,"type",&type)&&cb_text(&type,&str,&slen)&&slen==10&&
           !memcmp(str,"public-key",10)&&cb_map_text(desc,"id",&id)&&cb_bytes(&id,p,n);
}
static bool excluded(const cb_value *list,const uint8_t rp_hash[32]){
    if(list->type!=4)return false;
    for(size_t i=0;i<list->arg;i++){
        cb_value desc;const uint8_t *id;size_t n;
        if(cb_array_at(list,i,&desc)&&descriptor_id(&desc,&id,&n)&&fc_credential_valid(rp_hash,id,n))return true;
    }
    return false;
}
/* OpenSSH's key-selection probe uses getAssertion(options.up=false).
 * The probe must not wait for touch; the actual assertion must still require
 * a fresh user-presence edge. Only parse enough here to route the request.
 * Full validation takes place in get_assertion(). */
bool fido_is_preflight(const uint8_t *in, size_t in_len) {
    if (!in || in_len < 2 || in[0] != 2) return false;
    cb_value request, opts, up;
    bool requested_up;
    return cb_decode(in + 1, in_len - 1, &request) && request.type == 5 &&
           integer_key(&request, 5, &opts) && opts.type == 5 &&
           cb_map_text(&opts, "up", &up) && cb_boolean(&up, &requested_up) &&
           !requested_up;
}
static void get_info(uint8_t *out,size_t *olen){
    cb_writer w;out[0]=0;cb_init(&w,out+1,FIDO_CBOR_LIMIT-1);
    cb_head(&w,5,9); /* keys: 1 2 3 4 5 6 7 8 9 */
    cb_int(&w,1);cb_head(&w,4,1);cb_tstr(&w,"FIDO_2_0");
    cb_int(&w,2);cb_head(&w,4,1);cb_tstr(&w,"credProtect");
    cb_int(&w,3);cb_bstr(&w,aaguid,sizeof(aaguid));
    cb_int(&w,4);cb_head(&w,5,3);
      cb_tstr(&w,"rk");cb_head(&w,7,20);
      cb_tstr(&w,"up");cb_head(&w,7,21);
      cb_tstr(&w,"clientPin");cb_head(&w,7,fc_is_configured()?21:20);
    cb_int(&w,5);cb_int(&w,FIDO_CBOR_LIMIT);
    cb_int(&w,6);cb_head(&w,4,1);cb_int(&w,1); /* PIN/UV protocol 1 */
    cb_int(&w,7);cb_int(&w,8);
    cb_int(&w,8);cb_int(&w,FIDO_ID_LEN);
    cb_int(&w,9);cb_head(&w,4,1);cb_tstr(&w,"usb");
    if(!w.ok)error(out,olen,OTHER);else *olen=w.n+1;
}
/* PIN-token authorization is per clientDataHash and sets UV only if valid.
 * When locked, the browser has to obtain a token through clientPIN first. */
static bool authorize(const cb_value *req,int pin_key,int protocol_key,
                      const uint8_t client_hash[32],uint8_t *status,bool *uv){
    *uv=false;
    cb_value param,proto;
    bool has_param=integer_key(req,pin_key,&param);
    bool has_proto=integer_key(req,protocol_key,&proto);
    if(has_param != has_proto){*status=MISSING_PARAMETER;return false;}
    if(has_param){
        const uint8_t *auth;size_t auth_len;int64_t version;
        if(!cb_bytes(&param,&auth,&auth_len)||!cb_integer(&proto,&version)||version!=1){
            *status=PIN_AUTH_INVALID;return false;
        }
        if(auth_len==0){*status=PIN_REQUIRED;return false;}
        if(!fp_verify_auth(client_hash,auth,auth_len)){
            *status=PIN_AUTH_INVALID;return false;
        }
        *uv=true;
    }
    if(!fc_is_unlocked()){
        *status=fc_is_configured()?PIN_REQUIRED:PIN_NOT_SET;
        return false;
    }
    return true;
}
static void make_credential(const cb_value *map,bool touch_confirmed,uint8_t *out,size_t *olen){
    cb_value hash,rp,user,params,temp;
    const uint8_t *cdh,*rpname,*uid;size_t cdh_n,rp_n,uid_n;
    if(!integer_key(map,1,&hash)||!integer_key(map,2,&rp)||!integer_key(map,3,&user)||!integer_key(map,4,&params)){
        error(out,olen,MISSING_PARAMETER);return;
    }
    if(!cb_bytes(&hash,&cdh,&cdh_n)||cdh_n!=32||rp.type!=5||user.type!=5||params.type!=4 ||
       !text_value(&rp,"id",&rpname,&rp_n)||!valid_rp(rpname,rp_n)||
       !cb_map_text(&user,"id",&temp)||!cb_bytes(&temp,&uid,&uid_n)||uid_n==0||uid_n>64){
        error(out,olen,INVALID_CBOR);return;
    }
    (void)cdh;(void)uid;
    uint8_t status=0;
    if(!options(map,7,true,&status)){error(out,olen,status);return;}
    bool uv=false;
    if(!authorize(map,8,9,cdh,&status,&uv)){
        error(out,olen,status);return;
    }
    if(!permitted_alg(&params)){error(out,olen,UNSUPPORTED_ALGORITHM);return;}
    /* credProtect request is map key 6, {"credProtect": 1|2|3}.
     * Policies are stored as authenticated data in v2 credential IDs. */
    uint8_t cred_protect=1;
    bool cred_protect_requested=false;
    if(integer_key(map,6,&temp)){
        if(temp.type!=5){error(out,olen,INVALID_CBOR);return;}
        if(temp.arg){
            cb_value v;int64_t p;
            if(temp.arg!=1 || !cb_map_text(&temp,"credProtect",&v)){
                error(out,olen,UNSUPPORTED_OPTION);return;
            }
            if(!cb_integer(&v,&p) || p<1 || p>3){
                error(out,olen,INVALID_PARAMETER);return;
            }
            cred_protect=(uint8_t)p;
            cred_protect_requested=true;
        }
    }
    uint8_t rp_hash[32];if(!fc_sha256(rpname,rp_n,rp_hash)){error(out,olen,OTHER);return;}
    if(integer_key(map,5,&temp) && excluded(&temp,rp_hash)){
        error(out,olen,CREDENTIAL_EXCLUDED);return;
    }
    /* The host does not get to assert physical user presence. */
    if (!touch_confirmed) {error(out,olen,UP_REQUIRED);return;}
    uint8_t id[FIDO_ID_LEN],x[32],y[32];uint32_t cnt;
    if(!fc_credential_new_protected(rp_hash,cred_protect,id) || !fc_public_key(rp_hash,id,x,y) || !fc_counter_read(&cnt)){
        error(out,olen,OTHER);return;
    }
    uint8_t auth[256];cb_writer a;cb_init(&a,auth,sizeof(auth));
    uint8_t flags=(uint8_t)((uv?0x45:0x41) | (cred_protect_requested?0x80:0));
    uint8_t prefix[37];auth_prefix(prefix,rp_hash,flags,cnt);cb_raw(&a,prefix,sizeof(prefix));
    cb_raw(&a,aaguid,sizeof(aaguid));
    const uint8_t clen[2]={0,FIDO_ID_LEN};cb_raw(&a,clen,sizeof(clen));cb_raw(&a,id,sizeof(id));
    cb_head(&a,5,5); /* COSE EC2, ES256, secp256r1 */
    cb_int(&a,1);cb_int(&a,2);
    cb_int(&a,3);cb_int(&a,-7);
    cb_int(&a,-1);cb_int(&a,1);
    cb_int(&a,-2);cb_bstr(&a,x,32);
    cb_int(&a,-3);cb_bstr(&a,y,32);
    /* ED flag requires CBOR extension outputs after attestedCredentialData.
     * Never emit an unsolicited credProtect extension response. */
    if(cred_protect_requested){
        cb_head(&a,5,1);
        cb_tstr(&a,"credProtect");cb_int(&a,cred_protect);
    }
    if(!a.ok){error(out,olen,OTHER);return;}
    cb_writer w;out[0]=OK;cb_init(&w,out+1,FIDO_CBOR_LIMIT-1);
    cb_head(&w,5,3);
    cb_int(&w,1);cb_tstr(&w,"none");
    cb_int(&w,2);cb_bstr(&w,auth,a.n);
    cb_int(&w,3);cb_head(&w,5,0);
    if(!w.ok)error(out,olen,OTHER);else *olen=w.n+1;
}
static void get_assertion(const cb_value *map,bool touch_confirmed,uint8_t *out,size_t *olen){
    cb_value rp,hash,allow,tmp;
    const uint8_t *rpname,*cdh;size_t rp_n,cdh_n;
    if(!integer_key(map,1,&rp)||!integer_key(map,2,&hash)){error(out,olen,MISSING_PARAMETER);return;}
    if(!cb_text(&rp,&rpname,&rp_n)||!valid_rp(rpname,rp_n)||
       !cb_bytes(&hash,&cdh,&cdh_n)||cdh_n!=32){error(out,olen,INVALID_CBOR);return;}
    uint8_t status=0;
    if(!options(map,5,false,&status)){error(out,olen,status);return;}
    bool uv=false;
    if(!authorize(map,6,7,cdh,&status,&uv)){
        error(out,olen,status);return;
    }
    if(integer_key(map,4,&tmp)&& (tmp.type!=5 || tmp.arg)){
        error(out,olen,UNSUPPORTED_OPTION);return;
    }
    if(!integer_key(map,3,&allow)||allow.type!=4 || allow.arg==0){error(out,olen,NO_CREDENTIALS);return;}
    if(allow.arg>8){error(out,olen,INVALID_PARAMETER);return;}
    uint8_t rp_hash[32];if(!fc_sha256(rpname,rp_n,rp_hash)){error(out,olen,OTHER);return;}
    const uint8_t *id=NULL;size_t id_n=0;
    for(size_t i=0;i<allow.arg;i++){
        cb_value desc;const uint8_t *candidate;size_t n;
        if(cb_array_at(&allow,i,&desc)&&descriptor_id(&desc,&candidate,&n)&&fc_credential_valid(rp_hash,candidate,n)){
            id=candidate;id_n=n;break;
        }
    }
    if(!id){error(out,olen,NO_CREDENTIALS);return;}
    uint8_t cred_protect=0;
    if(!fc_credential_policy(rp_hash,id,id_n,&cred_protect)){
        error(out,olen,NO_CREDENTIALS);return;
    }
    /* A UV-required credential MUST NOT be usable merely because an earlier
     * PIN operation left the seed decrypted in RAM. Require a valid
     * per-request pinUvAuthParam (and set UV in signed authData). */
    if(cred_protect==3 && !uv){error(out,olen,PIN_REQUIRED);return;}
    /* An up:false CTAP2 preflight returns a genuine ES256 assertion with
     * UP=0. OpenSSH/libfido2 use this to select the matching authenticator.
     * Normal WebAuthn assertions MUST have an actual fresh touch to set UP=1. */
    cb_value opts, up;
    bool requested_up = true;
    if(integer_key(map,5,&opts) && cb_map_text(&opts,"up",&up)) {
        if(!cb_boolean(&up,&requested_up)) {error(out,olen,INVALID_CBOR);return;}
    }
    if(requested_up && !touch_confirmed) {error(out,olen,UP_REQUIRED);return;}
    uint8_t auth[37],prehash[69],digest[32],sig[80];size_t sig_n=0;uint32_t cnt=0;
    /* Silent preflight does not write NVS (untrusted hosts could exhaust flash
     * simply by probing). It signs the current counter without incrementing.
     * Authorised assertions still persist their next counter before signing. */
    if(requested_up) {
        if(!fc_counter_increment(&cnt)){error(out,olen,OTHER);return;}
    } else if(!fc_counter_read(&cnt)) {error(out,olen,OTHER);return;}
    auth_prefix(auth,rp_hash,(requested_up ? 0x01 : 0x00)|(uv ? 0x04 : 0),cnt);
    memcpy(prehash,auth,37);memcpy(prehash+37,cdh,32);
    if(!fc_sha256(prehash,sizeof(prehash),digest)||!fc_sign(rp_hash,id,digest,sig,&sig_n)){
        error(out,olen,OTHER);return;
    }
    cb_writer w;out[0]=OK;cb_init(&w,out+1,FIDO_CBOR_LIMIT-1);
    cb_head(&w,5,3);
    cb_int(&w,1);cb_head(&w,5,2);
      cb_tstr(&w,"id");cb_bstr(&w,id,id_n);
      cb_tstr(&w,"type");cb_tstr(&w,"public-key");
    cb_int(&w,2);cb_bstr(&w,auth,sizeof(auth));
    cb_int(&w,3);cb_bstr(&w,sig,sig_n);
    if(!w.ok)error(out,olen,OTHER);else *olen=w.n+1;
}
void fido_execute(const uint8_t *in,size_t in_len,bool touch_confirmed,
                  uint8_t out[FIDO_CBOR_LIMIT],size_t *olen){
    if(!out||!olen)return;
    error(out,olen,INVALID_COMMAND);
    if(in_len==0||!in)return;
    if(in[0]==4){if(in_len==1)get_info(out,olen);else error(out,olen,INVALID_CBOR);return;}
    if(in[0]!=1 && in[0]!=2 && in[0]!=6)return;
    cb_value request;
    if(in_len<2||!cb_decode(in+1,in_len-1,&request)||request.type!=5){error(out,olen,INVALID_CBOR);return;}
    if(in[0]==1)make_credential(&request,touch_confirmed,out,olen);
    else if(in[0]==2)get_assertion(&request,touch_confirmed,out,olen);
    else fp_execute(&request,out,olen);
}
