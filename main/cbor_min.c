#include "cbor_min.h"
#include <string.h>
#include <limits.h>
/* recursing into maps/arrays is bounded and every read is length-checked */
static bool item(const uint8_t *p, const uint8_t *end, const uint8_t **after,
                 cb_value *out, unsigned depth) {
    if (depth>10 || p>=end) return false;
    const uint8_t *start=p;uint8_t x=*p++,t=x>>5,ai=x&31;uint64_t a=0;
    if(ai<24) a=ai;
    else if(ai==24){if(end-p<1)return false;a=*p++;if(a<24)return false;}
    else if(ai==25){if(end-p<2)return false;a=((uint64_t)p[0]<<8)|p[1];p+=2;if(a<=255)return false;}
    else if(ai==26){if(end-p<4)return false;for(int i=0;i<4;i++)a=(a<<8)|*p++;if(a<=65535)return false;}
    else if(ai==27){if(end-p<8)return false;for(int i=0;i<8;i++)a=(a<<8)|*p++;if(a<=UINT32_MAX)return false;}
    else return false;
    const uint8_t *payload=p;
    if(t==2 || t==3){if(a>(uint64_t)(end-p))return false;p+=(size_t)a;}
    else if(t==4 || t==5){if(a>1024)return false;uint64_t items=a*(t==5?2u:1u);for(uint64_t i=0;i<items;i++){if(!item(p,end,&p,NULL,depth+1))return false;}}
    else if(t==0 || t==1){} /* signed integers */
    else if(t==7 && (a==20 || a==21 || a==22)){} /* false, true, null */
    else return false; /* no tags/floats/indefinite-length */
    if(out)*out=(cb_value){.p=payload,.n=(size_t)(p-payload),.type=t,.arg=a};
    if(after)*after=p;
    (void)start;return true;
}
bool cb_decode(const uint8_t *p,size_t n,cb_value *v){const uint8_t *end=p+n,*next=p;return p && item(p,end,&next,v,0) && next==end;}
static bool take(const uint8_t **cursor, const uint8_t *end,cb_value *v){return item(*cursor,end,cursor,v,0);}
static bool map_find(const cb_value *m,const char *str,int k,cb_value *out){
    if(m->type!=5)return false;
    const uint8_t *p=m->p,*end=p+m->n;bool found=false;
    for(size_t i=0;i<m->arg;i++){
        cb_value key,value;if(!take(&p,end,&key)||!take(&p,end,&value))return false;
        bool match=false;
        if(str)match=key.type==3 && strlen(str)==key.arg && !memcmp(str,key.p,(size_t)key.arg);
        else {int64_t val=0;match=cb_integer(&key,&val)&&val==k;}
        if(match){if(found)return false;*out=value;found=true;}
    }
    return found;
}
bool cb_map_int(const cb_value *m,int key,cb_value *out){return map_find(m,NULL,key,out);}
bool cb_map_text(const cb_value *m,const char *key,cb_value *out){return map_find(m,key,0,out);}
bool cb_array_at(const cb_value *a,size_t index,cb_value *out){
    if(a->type!=4 || index>=a->arg)return false;
    const uint8_t *p=a->p,*end=p+a->n;
    for(size_t i=0;i<=index;i++)if(!take(&p,end,out))return false;
    return true;
}
bool cb_bytes(const cb_value *v,const uint8_t **p,size_t *n){if(v->type!=2)return false;*p=v->p;*n=(size_t)v->arg;return true;}
bool cb_text(const cb_value *v,const uint8_t **p,size_t *n){if(v->type!=3)return false;*p=v->p;*n=(size_t)v->arg;return true;}
bool cb_boolean(const cb_value *v,bool *b){if(v->type!=7 || (v->arg!=20 && v->arg!=21))return false;*b=v->arg==21;return true;}
bool cb_integer(const cb_value *v,int64_t *n){if(v->type>1 || v->arg>INT64_MAX)return false;*n=v->type==0?(int64_t)v->arg:-1-(int64_t)v->arg;return true;}
void cb_init(cb_writer *w,uint8_t *buf,size_t max){*w=(cb_writer){.p=buf,.max=max,.n=0,.ok=true};}
void cb_raw(cb_writer *w,const uint8_t *p,size_t n){if(!w->ok || n>w->max-w->n){w->ok=false;return;}if(n)memcpy(w->p+w->n,p,n);w->n+=n;}
void cb_head(cb_writer *w,uint8_t type,uint64_t v){
    uint8_t buf[9];size_t n=1;buf[0]=type<<5;
    if(v<24)buf[0]|=(uint8_t)v;
    else if(v<=255){buf[0]|=24;buf[1]=(uint8_t)v;n=2;}
    else if(v<=65535){buf[0]|=25;buf[1]=(uint8_t)(v>>8);buf[2]=(uint8_t)v;n=3;}
    else if(v<=UINT32_MAX){buf[0]|=26;for(int i=0;i<4;i++)buf[1+i]=(uint8_t)(v>>(24-8*i));n=5;}
    else{buf[0]|=27;for(int i=0;i<8;i++)buf[1+i]=(uint8_t)(v>>(56-8*i));n=9;}
    cb_raw(w,buf,n);
}
void cb_int(cb_writer *w,int64_t n){if(n>=0)cb_head(w,0,(uint64_t)n);else cb_head(w,1,(uint64_t)(-1-n));}
void cb_bstr(cb_writer *w,const uint8_t *p,size_t n){cb_head(w,2,n);cb_raw(w,p,n);}
void cb_tstr(cb_writer *w,const char *s){size_t n=strlen(s);cb_head(w,3,n);cb_raw(w,(const uint8_t*)s,n);}
