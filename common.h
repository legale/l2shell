// common.h - Common definitions and structures for L2 shell

#ifndef COMMON_H
#define COMMON_H

#include <netinet/ether.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define CLIENT_SIGNATURE 0xAABBCCDD
#define SERVER_SIGNATURE 0xDDCCBBAA
#define SIGNATURE_LEN 4
#define MAX_PAYLOAD_SIZE 1024
#define ETHER_TYPE_CUSTOM 0x88B5
#define PACKET_DEDUP_CACHE 32
#define PACKET_DEDUP_WINDOW_NS 5000000ULL

// unit conversion macros
#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC 1000U
#endif

#ifndef USEC_PER_MSEC
#define USEC_PER_MSEC 1000U
#endif

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC 1000U
#endif

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC (USEC_PER_MSEC * NSEC_PER_USEC)
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC (MSEC_PER_SEC * USEC_PER_MSEC)
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC (MSEC_PER_SEC * NSEC_PER_MSEC)
#endif

extern const unsigned char broadcast_mac[ETH_ALEN];

typedef struct my_packet_header {
    struct ether_header eth_hdr;
    uint32_t signature;
    uint32_t payload_size;
    uint32_t crc;
} __attribute__((packed)) packh_t;

typedef struct my_packet {
    packh_t header;
    unsigned char payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed)) pack_t;

typedef struct packet_fingerprint {
    uint8_t mac[ETH_ALEN];
    uint32_t crc;
    uint32_t payload_size;
    uint32_t signature;
    struct timespec ts;
    int valid;
} packet_fingerprint_t;

typedef struct packet_dedup_cache {
    packet_fingerprint_t entries[PACKET_DEDUP_CACHE];
    size_t cursor;
} packet_dedup_t;

void enc_dec(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t len);
uint32_t calculate_checksum(const unsigned char *data, size_t len);
int build_packet(pack_t *packet, size_t payload_size, const uint8_t src_mac[ETH_ALEN], const uint8_t dst_mac[ETH_ALEN], uint32_t signature);
int parse_packet(pack_t *packet, ssize_t frame_len, uint32_t expected_signature);
void packet_dedup_init(packet_dedup_t *cache);
int packet_dedup_should_drop(packet_dedup_t *cache, const uint8_t mac[ETH_ALEN], uint32_t crc, uint32_t payload_size, uint32_t signature, uint64_t window_ns);

#endif // COMMON_H
