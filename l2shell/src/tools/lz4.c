// SPDX-License-Identifier: BSD-2-Clause
// Adapted from Linux kernel lib/lz4/lz4_compress.c (v6.1).

#include "lz4.h"

#include <stdint.h>
#include <string.h>

#define LZ4_MIN_MATCH 4
#define LZ4_HASH_LOG 16
#define LZ4_HASH_SIZE (1 << LZ4_HASH_LOG)
#define LZ4_RUN_MASK 0x0F
#define LZ4_ML_MASK 0x0F
#define LZ4_DISTANCE_MAX 65535
#define LZ4_LASTLITERALS 5
#define LZ4_MFLIMIT (LZ4_LASTLITERALS + LZ4_MIN_MATCH)
#define LZ4_SKIP_TRIGGER 6

static inline uint32_t lz4_read32(const unsigned char *src) {
    uint32_t v;
    memcpy(&v, src, sizeof(v));
    return v;
}

static inline uint32_t lz4_hash_sequence(uint32_t seq) {
    return (seq * 2654435761u) >> (32 - LZ4_HASH_LOG);
}

static inline unsigned char *lz4_write_length(unsigned char *op, size_t len) {
    while (len >= 0xFF) {
        *op++ = 0xFF;
        len -= 0xFF;
    }
    *op++ = (unsigned char)len;
    return op;
}

size_t lz4_compress_bound(size_t size) {
    return size + (size / 255) + 16;
}

int lz4_compress_default(const unsigned char *src, size_t src_size, unsigned char *dst, size_t dst_capacity) {
    const unsigned char *ip = src;
    const unsigned char *anchor = src;
    const unsigned char *iend = src + src_size;
    const unsigned char *mflimit = (src_size > LZ4_MFLIMIT) ? (iend - LZ4_MFLIMIT) : src;
    const unsigned char *matchlimit = (src_size > LZ4_LASTLITERALS) ? (iend - LZ4_LASTLITERALS) : src;
    unsigned char *op = dst;
    unsigned char *oend = dst + dst_capacity;
    int hash_table[LZ4_HASH_SIZE];

    if (!src_size || dst_capacity == 0)
        return 0;

    memset(hash_table, 0xFF, sizeof(hash_table));

    if (src_size < LZ4_MIN_MATCH)
        goto last_literals;

    while (ip <= mflimit) {
        const unsigned char *match;
        unsigned int step = 1;
        unsigned int search_match_nb = 1 << LZ4_SKIP_TRIGGER;

        do {
            uint32_t h = lz4_hash_sequence(lz4_read32(ip));
            match = src + hash_table[h];
            hash_table[h] = (int)(ip - src);
            if (match >= src && (ip - match) <= LZ4_DISTANCE_MAX && lz4_read32(match) == lz4_read32(ip))
                break;
            ip += step;
            if (ip > mflimit)
                goto last_literals;
            step = (search_match_nb++ >> LZ4_SKIP_TRIGGER) + 1;
        } while (1);

        while (ip > anchor && match > src && ip[-1] == match[-1]) {
            ip--;
            match--;
        }

        {
            size_t literal_len = (size_t)(ip - anchor);
            unsigned char *token;

            if (op + 1 + literal_len + 2 > oend)
                return 0;

            token = op++;
            if (literal_len >= LZ4_RUN_MASK) {
                *token = (unsigned char)(LZ4_RUN_MASK << 4);
                op = lz4_write_length(op, literal_len - LZ4_RUN_MASK);
            } else {
                *token = (unsigned char)(literal_len << 4);
            }

            memcpy(op, anchor, literal_len);
            op += literal_len;

            {
                size_t offset = (size_t)(ip - match);
                *op++ = (unsigned char)offset;
                *op++ = (unsigned char)(offset >> 8);
            }

            ip += LZ4_MIN_MATCH;
            match += LZ4_MIN_MATCH;
            while (ip < matchlimit && match < matchlimit && *ip == *match) {
                ip++;
                match++;
            }

            {
                size_t match_len = (size_t)(ip - anchor) - literal_len;
                if (match_len - LZ4_MIN_MATCH >= LZ4_ML_MASK) {
                    *token |= LZ4_ML_MASK;
                    op = lz4_write_length(op, match_len - LZ4_MIN_MATCH - LZ4_ML_MASK);
                } else {
                    *token |= (unsigned char)(match_len - LZ4_MIN_MATCH);
                }
            }

            anchor = ip;
        }
    }

last_literals:
    {
        size_t lit_len = (size_t)(iend - anchor);
        if (op + 1 + lit_len > oend)
            return 0;
        if (lit_len >= LZ4_RUN_MASK) {
            *op++ = (unsigned char)(LZ4_RUN_MASK << 4);
            op = lz4_write_length(op, lit_len - LZ4_RUN_MASK);
        } else {
            *op++ = (unsigned char)(lit_len << 4);
        }
        memcpy(op, anchor, lit_len);
        op += lit_len;
    }

    return (int)(op - dst);
}

int lz4_decompress_safe(const unsigned char *src, size_t src_size, unsigned char *dst, size_t dst_capacity) {
    const unsigned char *ip = src;
    const unsigned char *src_end = src + src_size;
    unsigned char *op = dst;
    unsigned char *dst_end = dst + dst_capacity;

    while (ip < src_end) {
        size_t literal_len;
        size_t match_len;
        uint16_t offset;
        const unsigned char *match;
        unsigned char token = *ip++;

        literal_len = token >> 4;
        if (literal_len == LZ4_RUN_MASK) {
            unsigned char s = 0;
            while (ip < src_end && (s = *ip++) == 0xFF)
                literal_len += 0xFF;
            if (ip > src_end)
                return -1;
            literal_len += s;
        }

        if (ip + literal_len > src_end || op + literal_len > dst_end)
            return -1;
        memcpy(op, ip, literal_len);
        ip += literal_len;
        op += literal_len;

        if (ip >= src_end)
            break;

        if (ip + 2 > src_end)
            return -1;
        offset = (uint16_t)ip[0] | ((uint16_t)ip[1] << 8);
        ip += 2;
        if (offset == 0 || offset > (size_t)(op - dst))
            return -1;
        match = op - offset;

        match_len = token & LZ4_ML_MASK;
        if (match_len == LZ4_ML_MASK) {
            unsigned char s = 0;
            while (ip < src_end && (s = *ip++) == 0xFF)
                match_len += 0xFF;
            if (ip > src_end)
                return -1;
            match_len += s;
        }
        match_len += LZ4_MIN_MATCH;

        if (op + match_len > dst_end)
            return -1;
        while (match_len--)
            *op++ = *match++;
    }

    return (int)(op - dst);
}
