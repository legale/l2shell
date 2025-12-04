#ifndef TEST_COMMON_SHARED_H
#define TEST_COMMON_SHARED_H

#include <string.h>

#include "common.h"

static inline void test_fill_payload(u8 *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (u8)(i & 0xff);
    }
}

static inline void test_set_macs(u8 src[ETH_ALEN], u8 dst[ETH_ALEN]) {
    const u8 src_template[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    const u8 dst_template[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02};
    memcpy(src, src_template, ETH_ALEN);
    memcpy(dst, dst_template, ETH_ALEN);
}

#endif /* TEST_COMMON_SHARED_H */
