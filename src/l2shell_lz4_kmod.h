// SPDX-License-Identifier: BSD-2-Clause
// Simplified LZ4 decoder shared by the kernel module.

#ifndef L2SHELL_LZ4_KMOD_H
#define L2SHELL_LZ4_KMOD_H

#include <linux/types.h>
#include <linux/string.h>

#define L2SHELL_LZ4_MIN_MATCH 4
#define L2SHELL_LZ4_RUN_MASK 0x0F
#define L2SHELL_LZ4_ML_MASK 0x0F

static inline int l2sh_lz4_decompress(const u8 *src, size_t src_size, u8 *dst, size_t dst_capacity)
{
    const u8 *ip = src;
    const u8 *src_end = src + src_size;
    u8 *op = dst;
    u8 *dst_end = dst + dst_capacity;

    while (ip < src_end) {
        size_t literal_len;
        size_t match_len;
        u16 offset;
        const u8 *match;
        u8 token = *ip++;

        literal_len = token >> 4;
        if (literal_len == L2SHELL_LZ4_RUN_MASK) {
            u8 s = 0;
            while (ip < src_end && (s = *ip++) == 0xFF)
                literal_len += 0xFF;
            if (ip > src_end)
                return -EIO;
            literal_len += s;
        }

        if (ip + literal_len > src_end || op + literal_len > dst_end)
            return -EIO;
        memcpy(op, ip, literal_len);
        ip += literal_len;
        op += literal_len;

        if (ip >= src_end)
            break;

        if (ip + 2 > src_end)
            return -EIO;
        offset = (u16)ip[0] | ((u16)ip[1] << 8);
        ip += 2;
        if (!offset || offset > (size_t)(op - dst))
            return -EIO;
        match = op - offset;

        match_len = token & L2SHELL_LZ4_ML_MASK;
        if (match_len == L2SHELL_LZ4_ML_MASK) {
            u8 s = 0;
            while (ip < src_end && (s = *ip++) == 0xFF)
                match_len += 0xFF;
            if (ip > src_end)
                return -EIO;
            match_len += s;
        }
        match_len += L2SHELL_LZ4_MIN_MATCH;

        if (op + match_len > dst_end)
            return -EIO;
        while (match_len--)
            *op++ = *match++;
    }

    return (int)(op - dst);
}

#endif
