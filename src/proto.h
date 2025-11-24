// proto.h - central wire-format definitions for L2 shell frames

#ifndef L2S_PROTO_H
#define L2S_PROTO_H

#include "hello_proto.h"
#include "intshort.h"

#include <netinet/ether.h>
#include <stddef.h>
#include <sys/types.h>

// EtherType carried by all L2 shell frames
#define ETHER_TYPE_CUSTOM 0x88B5

// Directional signatures used for lightweight authentication
#define CLIENT_SIGNATURE 0xAABBCCDDu
#define SERVER_SIGNATURE 0xDDCCBBAAu

// Payload layout: 16-byte nonce followed by encrypted payload
#define MAX_PAYLOAD_SIZE 1024
#define MAX_DATA_SIZE (MAX_PAYLOAD_SIZE - PACKET_NONCE_LEN)

// Optional semantic type for higher-level handlers
enum l2s_msg_type {
    L2S_MSG_UNKNOWN = 0,
    L2S_MSG_HELLO = 1,
    L2S_MSG_DATA = 2,
    L2S_MSG_CONTROL = 3,
};

// Unified header description for the on-wire frame.
// All multi-byte fields are stored in network order.
typedef struct l2s_frame_header {
    struct ether_header eth_hdr;
    u32 signature;
    u32 payload_size;
    u32 crc;
} __attribute__((packed)) l2s_frame_header_t;

typedef struct l2s_frame {
    l2s_frame_header_t header;
    u8 payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed)) l2s_frame_t;

// Parameters required to build a frame
typedef struct l2s_frame_meta {
    const u8 *src_mac;
    const u8 *dst_mac;
    u32 signature;
    enum l2s_msg_type type;
    u8 flags;
} l2s_frame_meta_t;

enum l2s_frame_error {
    L2S_FRAME_OK = 0,
    L2S_FRAME_ERR_ARG = -1,
    L2S_FRAME_ERR_LEN = -2,
    L2S_FRAME_ERR_RANGE = -3,
    L2S_FRAME_ERR_SIGNATURE = -4,
    L2S_FRAME_ERR_SHORT = -5,
    L2S_FRAME_ERR_CRC = -6,
    L2S_FRAME_ERR_FMT = -7,
};

size_t l2s_frame_wire_size(size_t payload_len);
int l2s_build_frame(l2s_frame_t *frame, size_t frame_capacity,
                    const l2s_frame_meta_t *meta,
                    const void *payload, size_t payload_len);
int l2s_parse_frame(l2s_frame_t *frame, size_t frame_len,
                    u32 expected_signature, size_t *payload_len_out);

int build_packet(l2s_frame_t *packet, size_t payload_size, const u8 src_mac[ETH_ALEN],
                 const u8 dst_mac[ETH_ALEN], u32 signature);
int parse_packet(l2s_frame_t *packet, ssize_t frame_len, u32 expected_signature);

#endif // L2S_PROTO_H
