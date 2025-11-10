// common.c - Common functions for packet handling

#include "common.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE 4

static const uint8_t key_magic[BLOCK_SIZE] = {4, 1, 2, 3};

const unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff,
                                               0xff, 0xff, 0xff};

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
  if (!packet || !src_mac || !dst_mac) {
    return -1;
  }
  if (payload_size > MAX_PAYLOAD_SIZE) {
    fprintf(stderr, "error: payload size too large: %zu\n", payload_size);
    return -1;
  }

  packet->header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
  memcpy(packet->header.eth_hdr.ether_shost, src_mac, ETH_ALEN);
  memcpy(packet->header.eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
  packet->header.signature = htonl(signature);
  packet->header.payload_size = htonl((uint32_t)payload_size);
  packet->header.crc = 0;

  size_t frame_len = sizeof(packh_t) + payload_size;
  uint32_t crc = calculate_checksum((const uint8_t *)packet, frame_len);
  packet->header.crc = crc;

  if (payload_size > 0) {
    enc_dec(packet->payload, packet->payload, (const uint8_t *)&packet->header.crc, payload_size);
  }

  return (int)frame_len;
}

int parse_packet(pack_t *packet, ssize_t frame_len, uint32_t expected_signature) {
  if (!packet || frame_len < (ssize_t)sizeof(packh_t)) {
    return -1;
  }

  size_t len = (size_t)frame_len;
  packh_t *header = &packet->header;

  if (ntohs(header->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM) {
    return -1;
  }

  if (ntohl(header->signature) != expected_signature) {
    return -1;
  }

  uint32_t payload_size = ntohl(header->payload_size);
  if (payload_size > MAX_PAYLOAD_SIZE) {
    fprintf(stderr, "error: payload size too large: %u\n", payload_size);
    return -1;
  }

  size_t expected_len = sizeof(packh_t) + payload_size;
  if (len < expected_len) {
    fprintf(stderr, "error: truncated packet: have=%zu expected=%zu\n", len, expected_len);
    return -1;
  }

  if (payload_size > 0) {
    enc_dec(packet->payload, packet->payload, (const uint8_t *)&packet->header.crc, payload_size);
  }

  uint32_t crc = header->crc;
  header->crc = 0;
  uint32_t crc_calc = calculate_checksum((const uint8_t *)packet, expected_len);
  header->crc = crc;

  if (crc != crc_calc) {
    fprintf(stderr, "error: crc mismatch: recv: %u expected: %u\n", crc, crc_calc);
    return -1;
  }

  return (int)payload_size;
}

void packet_dedup_init(packet_dedup_t *cache) {
  if (!cache) return;
  memset(cache, 0, sizeof(*cache));
}

static inline uint64_t timespec_to_ns(const struct timespec *ts) {
  return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
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
