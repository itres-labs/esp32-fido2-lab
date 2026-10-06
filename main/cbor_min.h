#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct { const uint8_t *p; size_t n; uint8_t type; uint64_t arg; } cb_value;
typedef struct { uint8_t *p; size_t max, n; bool ok; } cb_writer;
/* Strict, bounded, definite-length CBOR subset; all item sizes are verified. */
bool cb_decode(const uint8_t *p,size_t n,cb_value *v);
bool cb_map_int(const cb_value *map,int key,cb_value *out);
bool cb_map_text(const cb_value *map,const char *key,cb_value *out);
bool cb_array_at(const cb_value *arr,size_t i,cb_value *out);
bool cb_bytes(const cb_value *v,const uint8_t **p,size_t *n);
bool cb_text(const cb_value *v,const uint8_t **p,size_t *n);
bool cb_boolean(const cb_value *v,bool *b);
bool cb_integer(const cb_value *v,int64_t *n);
void cb_init(cb_writer *w,uint8_t *buf,size_t max);
void cb_head(cb_writer *w,uint8_t type,uint64_t v);
void cb_int(cb_writer *w,int64_t n);
void cb_bstr(cb_writer *w,const uint8_t *p,size_t n);
void cb_tstr(cb_writer *w,const char *s);
void cb_raw(cb_writer *w,const uint8_t *p,size_t n);
