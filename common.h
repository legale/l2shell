// common.h - Common definitions and structures for L2 shell

#ifndef COMMON_H
#define COMMON_H

#include "intshort.h"
#include "hello_proto.h"

#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#endif

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

extern const u8 broadcast_mac[ETH_ALEN];

typedef struct my_packet_header {
    struct ether_header eth_hdr;
    u32 signature;
    u32 payload_size;
    u32 crc;
} __attribute__((packed)) packh_t;

typedef struct my_packet {
    packh_t header;
    u8 payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed)) pack_t;

typedef struct packet_fingerprint {
    u8 mac[ETH_ALEN];
    u32 crc;
    u32 payload_size;
    u32 signature;
    struct timespec ts;
    int valid;
} packet_fingerprint_t;

typedef struct packet_dedup_cache {
    packet_fingerprint_t entries[PACKET_DEDUP_CACHE];
    size_t cursor;
} packet_dedup_t;

void enc_dec(const u8 *input, u8 *output, const u8 *key, size_t len);
u32 calculate_checksum(const u8 *data, size_t len);
int build_packet(pack_t *packet, size_t payload_size, const u8 src_mac[ETH_ALEN], const u8 dst_mac[ETH_ALEN], u32 signature);
int parse_packet(pack_t *packet, ssize_t frame_len, u32 expected_signature);
void packet_dedup_init(packet_dedup_t *cache);
int packet_dedup_should_drop(packet_dedup_t *cache, const u8 mac[ETH_ALEN], u32 crc, u32 payload_size, u32 signature, u64 window_ns);

void debug_dump_frame(const char *prefix, const u8 *data, size_t len);
int init_packet_socket(int *sockfd, struct ifreq *ifr, struct sockaddr_ll *bind_addr, const char *iface, int bind_to_device);
void deinit_packet_socket(int *sockfd);
void log_info(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_error(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void log_error_errno(const char *tag, const char *op);

#endif // COMMON_H
