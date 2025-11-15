// SPDX-License-Identifier: BSD-2-Clause
// Derived from Linux kernel lib/lz4/lz4defs.h (v6.1).

#ifndef L2SHELL_LZ4_H
#define L2SHELL_LZ4_H

#include <stddef.h>

size_t lz4_compress_bound(size_t size);
int lz4_compress_default(const unsigned char *src, size_t src_size, unsigned char *dst, size_t dst_capacity);
int lz4_decompress_safe(const unsigned char *src, size_t src_size, unsigned char *dst, size_t dst_capacity);

#endif
