// proto.c - wire-format helpers for L2 shell frames

#include "proto.h"
#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

static size_t l2s_payload_with_nonce(size_t data_len) {
    return PACKET_NONCE_LEN + data_len;
}

size_t l2s_frame_wire_size(size_t payload_len) {
    if (payload_len > MAX_DATA_SIZE)
        return 0;
    return sizeof(l2s_frame_header_t) + l2s_payload_with_nonce(payload_len);
}

static int l2s_validate_build_args(const l2s_frame_t *frame, size_t frame_capacity,
                                   const l2s_frame_meta_t *meta, const void *payload,
                                   size_t payload_len) {
    if (!frame || !meta || !meta->src_mac || !meta->dst_mac)
        return L2S_FRAME_ERR_ARG;
    if (payload_len > 0 && !payload)
        return L2S_FRAME_ERR_ARG;
    if (payload_len > MAX_DATA_SIZE)
        return L2S_FRAME_ERR_RANGE;
    if (frame_capacity < sizeof(l2s_frame_header_t))
        return L2S_FRAME_ERR_LEN;
    if (frame_capacity < l2s_frame_wire_size(payload_len))
        return L2S_FRAME_ERR_LEN;
    return L2S_FRAME_OK;
}

int l2s_build_frame(l2s_frame_t *frame, size_t frame_capacity,
                    const l2s_frame_meta_t *meta,
                    const void *payload, size_t payload_len) {
    u8 *nonce_ptr;
    u8 *data_ptr;
    size_t enc_payload_len;
    size_t frame_len;
    int rc = l2s_validate_build_args(frame, frame_capacity, meta, payload, payload_len);
    if (rc != L2S_FRAME_OK)
        return rc;

    enc_payload_len = l2s_payload_with_nonce(payload_len);
    frame_len = sizeof(l2s_frame_header_t) + enc_payload_len;

    frame->header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
    memcpy(frame->header.eth_hdr.ether_shost, meta->src_mac, ETH_ALEN);
    memcpy(frame->header.eth_hdr.ether_dhost, meta->dst_mac, ETH_ALEN);
    frame->header.signature = htonl(meta->signature);
    frame->header.payload_size = htonl((u32)enc_payload_len);
    frame->header.crc = 0;

    nonce_ptr = frame->payload;
    data_ptr = frame->payload + PACKET_NONCE_LEN;

    if (payload_len > 0) {
        memmove(data_ptr, payload, payload_len);
    }

    hello_generate_nonce(nonce_ptr, PACKET_NONCE_LEN);
    if (payload_len > 0) {
        for (size_t i = 0; i < payload_len; i++)
            data_ptr[i] ^= nonce_ptr[i & (PACKET_NONCE_LEN - 1)];
        enc_dec(data_ptr, data_ptr, l2s_shared_key, payload_len);
    }

    frame->header.crc = 0;
    u32 crc = csum32((const u8 *)frame, frame_len);
    frame->header.crc = htonl(crc);

    if (payload_len > 0)
        enc_dec(data_ptr, data_ptr, (const u8 *)&frame->header.crc, payload_len);

    return (int)frame_len;
}

static int l2s_validate_parse_args(const l2s_frame_t *frame, size_t frame_len) {
    if (!frame)
        return L2S_FRAME_ERR_ARG;
    if (frame_len < sizeof(l2s_frame_header_t))
        return L2S_FRAME_ERR_SHORT;
    return L2S_FRAME_OK;
}

int l2s_parse_frame(l2s_frame_t *frame, size_t frame_len,
                    u32 expected_signature, size_t *payload_len_out) {
    u32 payload_size_net;
    u32 payload_size_host;
    size_t expected_len;
    size_t data_len;
    u32 crc_host;
    u32 crc_calc;
    u8 *nonce_ptr;
    u8 *data_ptr;

    int rc = l2s_validate_parse_args(frame, frame_len);
    if (rc != L2S_FRAME_OK)
        return rc;

    if (ntohs(frame->header.eth_hdr.ether_type) != ETHER_TYPE_CUSTOM)
        return L2S_FRAME_ERR_ARG;

    payload_size_net = frame->header.payload_size;
    payload_size_host = ntohl(payload_size_net);
    if (payload_size_host > MAX_PAYLOAD_SIZE)
        return L2S_FRAME_ERR_RANGE;
    if (payload_size_host < PACKET_NONCE_LEN)
        return L2S_FRAME_ERR_FMT;

    expected_len = sizeof(l2s_frame_header_t) + payload_size_host;
    if (frame_len < expected_len) {
        log_error("packet", "event=frame_truncated len=%zu need=%zu", frame_len, expected_len);
        return L2S_FRAME_ERR_SHORT;
    }

    if (ntohl(frame->header.signature) != expected_signature)
        return L2S_FRAME_ERR_SIGNATURE;

    crc_host = ntohl(frame->header.crc);
    data_len = payload_size_host - PACKET_NONCE_LEN;
    nonce_ptr = frame->payload;
    data_ptr = frame->payload + PACKET_NONCE_LEN;

    if (data_len > 0)
        enc_dec(data_ptr, data_ptr, (const u8 *)&frame->header.crc, data_len);

    frame->header.crc = 0;
    crc_calc = csum32((const u8 *)frame, expected_len);
    frame->header.crc = htonl(crc_host);

    if (crc_host != crc_calc) {
        log_error("packet", "event=crc_mismatch recv=%u calc=%u", crc_host, crc_calc);
        return L2S_FRAME_ERR_CRC;
    }

    if (data_len > 0) {
        enc_dec(data_ptr, data_ptr, l2s_shared_key, data_len);
        for (size_t i = 0; i < data_len; i++)
            data_ptr[i] ^= nonce_ptr[i & (PACKET_NONCE_LEN - 1)];
        memmove(frame->payload, data_ptr, data_len);
    }

    if (payload_len_out)
        *payload_len_out = data_len;
    return L2S_FRAME_OK;
}

int build_packet(pack_t *packet, size_t payload_size, const u8 src_mac[ETH_ALEN],
                 const u8 dst_mac[ETH_ALEN], u32 signature) {
    l2s_frame_meta_t meta = {
        .src_mac = src_mac,
        .dst_mac = dst_mac,
        .signature = signature,
        .type = L2S_MSG_DATA,
        .flags = 0,
    };
    return l2s_build_frame(packet, sizeof(*packet), &meta, payload_size > 0 ? packet->payload : NULL, payload_size);
}

int parse_packet(pack_t *packet, ssize_t frame_len, u32 expected_signature) {
    size_t payload_len = 0;
    int rc;

    if (frame_len < 0)
        return L2S_FRAME_ERR_SHORT;

    rc = l2s_parse_frame(packet, (size_t)frame_len, expected_signature, &payload_len);
    if (rc != L2S_FRAME_OK)
        return rc;
    return (int)payload_len;
}
