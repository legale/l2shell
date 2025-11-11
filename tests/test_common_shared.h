#ifndef TEST_COMMON_SHARED_H
#define TEST_COMMON_SHARED_H

#include <stdint.h>
#include <string.h>

#include "common.h"

static inline void test_fill_payload(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xff);
    }
}

static inline void test_set_macs(uint8_t src[ETH_ALEN], uint8_t dst[ETH_ALEN]) {
    const uint8_t src_template[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01};
    const uint8_t dst_template[ETH_ALEN] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02};
    memcpy(src, src_template, ETH_ALEN);
    memcpy(dst, dst_template, ETH_ALEN);
}

#endif /* TEST_COMMON_SHARED_H */
