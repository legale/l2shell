// frame_dedup.h - shared helper for fast frame deduplication

#ifndef FRAME_DEDUP_H
#define FRAME_DEDUP_H

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#endif

typedef struct frame_dedup_entry {
    u64 ts_ns;
    size_t len;
    u32 checksum;
    int ifindex;
    int valid;
} frame_dedup_entry_t;

typedef struct frame_dedup_cache {
    frame_dedup_entry_t *slots;
    size_t capacity;
    size_t cursor;
} frame_dedup_cache_t;

static inline void frame_dedup_init(frame_dedup_cache_t *cache,
                                    frame_dedup_entry_t *storage,
                                    size_t capacity) {
    if (!cache || !storage || capacity == 0)
        return;
    cache->slots = storage;
    cache->capacity = capacity;
    cache->cursor = 0;
    memset(cache->slots, 0, capacity * sizeof(*cache->slots));
}

static inline void frame_dedup_reset(frame_dedup_cache_t *cache) {
    if (!cache || !cache->slots || cache->capacity == 0)
        return;
    memset(cache->slots, 0, cache->capacity * sizeof(*cache->slots));
    cache->cursor = 0;
}

static inline int frame_dedup_should_drop(frame_dedup_cache_t *cache,
                                          size_t len,
                                          u32 checksum,
                                          int ifindex,
                                          u64 now_ns,
                                          u64 window_ns,
                                          int *prev_ifindex,
                                          u64 *age_ns) {
    if (!cache || !cache->slots || cache->capacity == 0)
        return 0;
    if (ifindex < 0)
        ifindex = 0;

    for (size_t i = 0; i < cache->capacity; i++) {
        frame_dedup_entry_t *entry = &cache->slots[i];
        if (!entry->valid)
            continue;
        if (now_ns > entry->ts_ns && now_ns - entry->ts_ns > window_ns) {
            entry->valid = 0;
            continue;
        }
        if (entry->valid && entry->len == len && entry->checksum == checksum) {
            u64 age = (now_ns >= entry->ts_ns) ? (now_ns - entry->ts_ns) : 0;
            if (entry->ifindex == 0 || ifindex == 0 || entry->ifindex == ifindex) {
                entry->ts_ns = now_ns;
                entry->ifindex = ifindex ? ifindex : entry->ifindex;
                return 0;
            }
            if (prev_ifindex)
                *prev_ifindex = entry->ifindex;
            if (age_ns)
                *age_ns = age;
            entry->ts_ns = now_ns;
            entry->ifindex = ifindex;
            return 1;
        }
    }

    frame_dedup_entry_t *slot = &cache->slots[cache->cursor];
    slot->ts_ns = now_ns;
    slot->len = len;
    slot->checksum = checksum;
    slot->ifindex = ifindex;
    slot->valid = 1;
    cache->cursor = (cache->cursor + 1) % cache->capacity;
    return 0;
}

#endif // FRAME_DEDUP_H
