// common.c - Common functions for packet handling

#include "common.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE 4

static const uint8_t key_magic[BLOCK_SIZE] = {4, 1, 2, 3};
static const uint8_t zero_key[BLOCK_SIZE] = {0, 0, 0, 0};

const unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void enc_dec(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t len) {
    if (len == 0) return;

    uint8_t temp[BLOCK_SIZE];

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        size_t chunk = len - i < BLOCK_SIZE ? len - i : BLOCK_SIZE;
        for (size_t j = 0; j < chunk; j++) {
            temp[j] = input[i + j] ^ key[j] ^ key_magic[j];
        }
        for (size_t j = 0; j < chunk; j++) {
            output[i + j] = temp[j];
        }
    }
}

uint32_t calculate_checksum(const unsigned char *data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum += data[i];
    }
    return checksum;
}

int build_packet(pack_t *packet, size_t payload_size, const uint8_t src_mac[ETH_ALEN],
                 const uint8_t dst_mac[ETH_ALEN], uint32_t signature) {
    if (!packet || !src_mac || !dst_mac) return -1;
    if (payload_size > MAX_PAYLOAD_SIZE) return -1;

    /* fill header */
    packet->header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
    memcpy(packet->header.eth_hdr.ether_shost, src_mac, ETH_ALEN);
    memcpy(packet->header.eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
    packet->header.signature = htonl(signature);
    packet->header.payload_size = htonl((uint32_t)payload_size);
    packet->header.crc = 0;

    /* encrypt first, using provisional key = 0 (stable step) */
    if (payload_size > 0) {
        /* key is final crc bytes; to make deterministic we do two-pass:
         * pass1: encrypt with zero key to stabilize plaintext-dependent crc
         */
        enc_dec(packet->payload, packet->payload, zero_key, payload_size);
    }

    /* crc over header(with crc=0) + encrypted payload */
    size_t frame_len = sizeof(packh_t) + payload_size;
    uint32_t crc = calculate_checksum((const uint8_t *)packet, frame_len);

    /* write crc */
    packet->header.crc = htonl(crc);

    /* re-encrypt with final key so both sides share same rule */
    if (payload_size > 0) {
        enc_dec(packet->payload, packet->payload, (const uint8_t *)&packet->header.crc, payload_size);
    }

    return (int)frame_len;
}

int parse_packet(pack_t *packet, ssize_t frame_len, uint32_t expected_signature) {
    if (!packet || frame_len < (ssize_t)sizeof(packh_t)) return -1;

    size_t len = (size_t)frame_len;
    packh_t *h = &packet->header;

    if (ntohs(h->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM) return -1;
    if (ntohl(h->signature) != expected_signature) return -1;

    uint32_t payload_size = ntohl(h->payload_size);
    if (payload_size > MAX_PAYLOAD_SIZE) return -1;

    size_t expected_len = sizeof(packh_t) + payload_size;
    if (len < expected_len) return -1;

    uint32_t crc_net = h->crc;
    uint32_t crc_host = ntohl(crc_net);

    if (payload_size > 0) {
        enc_dec(packet->payload, packet->payload, (const uint8_t *)&crc_net, payload_size);
    }

    h->crc = 0;
    uint32_t crc_calc = calculate_checksum((const uint8_t *)packet, expected_len);
    h->crc = crc_net;

    if (crc_host != crc_calc) {
        fprintf(stderr, "error: crc mismatch: recv=%u calc=%u\n",
                crc_host, crc_calc);
        return -1;
    }

    if (payload_size > 0) {
        enc_dec(packet->payload, packet->payload, zero_key, payload_size);
    }

    return (int)payload_size;
}

void packet_dedup_init(packet_dedup_t *cache) {
    if (!cache) return;
    memset(cache, 0, sizeof(*cache));
}

static inline uint64_t timespec_to_ns(const struct timespec *ts) {
    return (uint64_t)ts->tv_sec * NSEC_PER_SEC + (uint64_t)ts->tv_nsec;
}

int packet_dedup_should_drop(packet_dedup_t *cache, const uint8_t mac[ETH_ALEN],
                             uint32_t crc, uint32_t payload_size, uint32_t signature,
                             uint64_t window_ns) {
    if (!cache || !mac) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t now_ns = timespec_to_ns(&now);

    for (size_t i = 0; i < PACKET_DEDUP_CACHE; i++) {
        packet_fingerprint_t *entry = &cache->entries[i];
        if (!entry->valid) continue;
        uint64_t entry_ns = timespec_to_ns(&entry->ts);
        if (now_ns > entry_ns && now_ns - entry_ns > window_ns) {
            entry->valid = 0;
            continue;
        }
        if (entry->valid &&
            entry->crc == crc &&
            entry->payload_size == payload_size &&
            entry->signature == signature &&
            memcmp(entry->mac, mac, ETH_ALEN) == 0) {
            return 1;
        }
    }

    packet_fingerprint_t *slot = &cache->entries[cache->cursor];
    memcpy(slot->mac, mac, ETH_ALEN);
    slot->crc = crc;
    slot->payload_size = payload_size;
    slot->signature = signature;
    slot->ts = now;
    slot->valid = 1;

    cache->cursor = (cache->cursor + 1) % PACKET_DEDUP_CACHE;
    return 0;
}

void debug_dump_frame(const char *prefix, const uint8_t *data, size_t len) {
    if (!data || !len) return;

    FILE *log_file = fopen("clientserver.log", "a");
    if (!log_file) return;

    fprintf(log_file, "%s len=%zu\n", prefix, len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(log_file, "%04zx:", i);
        size_t line_end = (i + 16 < len) ? i + 16 : len;
        for (size_t j = i; j < line_end; ++j) {
            fprintf(log_file, " %02x", data[j]);
        }
        fputc('\n', log_file);
    }

    fclose(log_file);
}
