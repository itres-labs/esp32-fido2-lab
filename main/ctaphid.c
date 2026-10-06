#include "ctaphid.h"
#include "fido_engine.h"
#include "fido_crypto.h"
#include <string.h>

#define CMD_PING    0x01
#define CMD_MSG     0x03
#define CMD_LOCK    0x04
#define CMD_INIT    0x06
#define CMD_WINK    0x08
#define CMD_CBOR    0x10
#define CMD_CANCEL  0x11
#define CMD_ERROR   0x3f
#define CMD_KEEPALIVE 0x3b
#define ERROR_INVALID_CMD 0x01
#define ERROR_INVALID_LEN 0x03
#define ERROR_INVALID_SEQ 0x04
#define ERROR_TIMEOUT 0x05
#define ERROR_BUSY 0x06
#define ERROR_INVALID_CHANNEL 0x0b

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static void put_be32(uint8_t *p, uint32_t n) {
    p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=(uint8_t)n;
}
static bool known(const ctaphid_t *h, uint32_t cid) {
    for (unsigned i=0; i<CTAPHID_MAX_CHANNELS; ++i) {
        if (h->channels[i] && h->channels[i]==cid) return true;
    }
    return false;
}
static void reset_pending(ctaphid_t *h) {
    h->active_cid=0; h->received=0; h->expected=0; h->next_seq=0; h->pending_cmd=0;
    h->waiting_for_touch=false;h->last_keepalive_ms=0;
    memset(h->buffer,0,sizeof(h->buffer));
}
static void reply(ctaphid_t *h, uint32_t cid, uint8_t command, const uint8_t *buf, size_t size) {
    uint8_t packet[CTAPHID_FRAME_SIZE]={0};
    if (size>CTAPHID_MAX_MSG) return;
    put_be32(packet,cid);
    packet[4]=command|0x80;
    packet[5]=(uint8_t)(size>>8); packet[6]=(uint8_t)size;
    size_t off=0;
    size_t n=size<57?size:57;
    if (n) memcpy(packet+7,buf,n);
    h->emit(packet,h->ctx);
    off=n;
    uint8_t seq=0;
    while (off<size) {
        memset(packet,0,sizeof(packet));
        put_be32(packet,cid); packet[4]=seq++;
        n=(size-off)<59?(size-off):59;
        memcpy(packet+5,buf+off,n);
        h->emit(packet,h->ctx);
        off+=n;
    }
}
static void err(ctaphid_t *h,uint32_t cid,uint8_t value) {
    reply(h,cid,CMD_ERROR,&value,1);
}
/* Resource-bounded CID management: never evict an in-flight transaction.
 * When all slots are occupied, replace the oldest idle CID. The host may
 * reinitialize a channel if its stale CID was recycled. */
static uint32_t allocate(ctaphid_t *h, uint32_t ms) {
    int slot = -1;
    for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++) {
        if (!h->channels[i]) {slot = i; break;}
    }
    if (slot < 0) {
        uint32_t max_age = 0;
        for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++) {
            if (h->channels[i] == h->active_cid) continue;
            uint32_t age = (uint32_t)(ms - h->channel_last_seen_ms[i]);
            if (slot < 0 || age > max_age) {
                slot = i;
                max_age = age;
            }
        }
    }
    if (slot < 0) return 0;
    for (int attempt = 0; attempt < 32; attempt++) {
        uint32_t cid = h->random(h->ctx);
        if (cid != 0 && cid != CTAPHID_BROADCAST && !known(h, cid)) {
            h->channels[slot] = cid;
            h->channel_last_seen_ms[slot] = ms;
            return cid;
        }
    }
    return 0;
}
void ctaphid_init(ctaphid_t *h,ctaphid_emit_t emit,ctaphid_random_t random,void *ctx) {
    memset(h,0,sizeof(*h)); h->emit=emit; h->random=random; h->ctx=ctx;
}
/* The user-presence wait is a non-blocking state machine. USB events and CANCEL
 * continue to be processed while CTAPHID_KEEPALIVE(UP_NEEDED) is emitted. */
static void process(ctaphid_t *h) {
    uint32_t cid=h->active_cid;
    const uint8_t *p=h->buffer;
    uint16_t len=h->expected;
    if(h->pending_cmd==CMD_CBOR){
        if(fc_is_unlocked() && len>0 &&
           (p[0]==0x01 || (p[0]==0x02 && !fido_is_preflight(p,len)))){
            h->waiting_for_touch=true; /* Only a NEW edge can finish it. */
            return;
        }
        uint8_t response[CTAPHID_MAX_MSG];size_t size=0;
        fido_execute(p,len,false,response,&size);
        reply(h,cid,CMD_CBOR,response,size);
    }else if(h->pending_cmd==CMD_PING){reply(h,cid,CMD_PING,p,len);}
    else if(h->pending_cmd==CMD_WINK && len==0){reply(h,cid,CMD_WINK,NULL,0);}
    else if(h->pending_cmd==CMD_WINK){err(h,cid,ERROR_INVALID_LEN);}
    else{err(h,cid,ERROR_INVALID_CMD);}
    reset_pending(h);
}
void ctaphid_touch(ctaphid_t *h,uint32_t ms){
    if(!h->active_cid || !h->waiting_for_touch ||
       (uint32_t)(ms-h->started_ms)<120u)return;
    uint8_t response[CTAPHID_MAX_MSG];size_t size=0;
    uint32_t cid=h->active_cid;
    fido_execute(h->buffer,h->expected,true,response,&size);
    reply(h,cid,CMD_CBOR,response,size);
    reset_pending(h);
}
void ctaphid_tick(ctaphid_t *h,uint32_t ms){
    if(!h->active_cid)return;
    uint32_t elapsed=(uint32_t)(ms-h->started_ms);
    if(h->waiting_for_touch){
        if(elapsed>30000u){
            uint32_t cid=h->active_cid;
            const uint8_t status=0x2f; /* CTAP2_ERR_USER_ACTION_TIMEOUT */
            reset_pending(h);reply(h,cid,CMD_CBOR,&status,1);return;
        }
        if((uint32_t)(ms-h->last_keepalive_ms)>=100u){
            uint8_t status=0x02; /* UP_NEEDED */
            reply(h,h->active_cid,CMD_KEEPALIVE,&status,1);
            h->last_keepalive_ms=ms;
        }
    }else if(elapsed>3000u){
        uint32_t cid=h->active_cid;
        reset_pending(h);err(h,cid,ERROR_TIMEOUT);
    }
}
void ctaphid_receive(ctaphid_t *h,const uint8_t f[CTAPHID_FRAME_SIZE],uint32_t ms) {
    uint32_t cid=get_be32(f);
    ctaphid_tick(h,ms);
    /* A valid channel stays recent while its owner actually uses it. */
    for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++) {
        if (h->channels[i] == cid) {
            h->channel_last_seen_ms[i] = ms;
            break;
        }
    }
    if (f[4]&0x80) {
        uint8_t cmd=f[4]&0x7f;
        uint16_t len=(uint16_t)((f[5]<<8)|f[6]);
        if (cmd==CMD_INIT) {
            if (len!=8) {err(h,cid,ERROR_INVALID_LEN);return;}
            if (cid!=CTAPHID_BROADCAST && !known(h,cid)) {err(h,cid,ERROR_INVALID_CHANNEL);return;}
            if (h->active_cid==cid) reset_pending(h);
            uint32_t allocated=(cid==CTAPHID_BROADCAST)?allocate(h,ms):cid;
            if (!allocated) {err(h,cid,ERROR_BUSY);return;}
            uint8_t v[17]={0}; memcpy(v,f+7,8); put_be32(v+8,allocated);
            v[12]=2; v[13]=0; v[14]=1; v[15]=0;
            v[16]=0x04|0x08; /* CBOR soportado, CTAP1_MSG no soportado */
            reply(h,cid,CMD_INIT,v,sizeof(v)); return;
        }
        if (!known(h,cid)) {err(h,cid,ERROR_INVALID_CHANNEL);return;}
        if (cmd==CMD_CANCEL) {
            if(cid==h->active_cid && h->waiting_for_touch && len==0)
                reset_pending(h); /* CTAPHID_CANCEL itself has no response */
            return;
        }
        if (h->active_cid) {err(h,cid,ERROR_BUSY);return;}
        if (len>CTAPHID_MAX_MSG) {err(h,cid,ERROR_INVALID_LEN);return;}
        h->active_cid=cid;h->started_ms=ms;h->last_keepalive_ms=ms;
        h->expected=len;h->next_seq=0;
        h->pending_cmd=cmd;
        h->received=len<57?len:57;
        if (h->received) memcpy(h->buffer,f+7,h->received);
        if (h->received==h->expected) process(h);
    } else {
        if (!known(h,cid)) {err(h,cid,ERROR_INVALID_CHANNEL);return;}
        if (!h->active_cid || cid!=h->active_cid) {err(h,cid,ERROR_INVALID_SEQ);return;}
        if (f[4]!=h->next_seq) {
            reset_pending(h);err(h,cid,ERROR_INVALID_SEQ);return;
        }
        h->next_seq++;
        uint16_t left=h->expected-h->received;
        uint16_t n=left<59?left:59;
        memcpy(h->buffer+h->received,f+5,n);
        h->received+=n;
        if (h->received==h->expected) process(h);
    }
}
