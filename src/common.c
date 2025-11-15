// common.c - Common functions for packet handling

#include "common.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h> //fchmod
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

const u8 broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
int build_packet(pack_t *packet, size_t payload_size, const u8 src_mac[ETH_ALEN],
                 const u8 dst_mac[ETH_ALEN], u32 signature) {
    if (!packet || !src_mac || !dst_mac) return -1;
    if (payload_size > MAX_PAYLOAD_SIZE) return -1;

    /* fill header */
    packet->header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
    memcpy(packet->header.eth_hdr.ether_shost, src_mac, ETH_ALEN);
    memcpy(packet->header.eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
    packet->header.signature = htonl(signature);
    packet->header.payload_size = htonl((u32)payload_size);
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
    u32 crc = csum32((const u8 *)packet, frame_len);

    /* write crc */
    packet->header.crc = htonl(crc);

    /* re-encrypt with final key so both sides share same rule */
    if (payload_size > 0) {
        enc_dec(packet->payload, packet->payload, (const u8 *)&packet->header.crc, payload_size);
    }

    return (int)frame_len;
}

int parse_packet(pack_t *packet, ssize_t frame_len, u32 expected_signature) {
    if (!packet || frame_len < (ssize_t)sizeof(packh_t)) return -1;

    size_t len = (size_t)frame_len;
    packh_t *h = &packet->header;

    if (ntohs(h->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM) return -1;
    if (ntohl(h->signature) != expected_signature) return -1;

    u32 payload_size = ntohl(h->payload_size);
    if (payload_size > MAX_PAYLOAD_SIZE) {
        log_error("packet", "event=payload_too_large size=%u limit=%u",
                  payload_size, MAX_PAYLOAD_SIZE);
        return -1;
    }

    size_t expected_len = sizeof(packh_t) + payload_size;
    if (len < expected_len) {
        log_error("packet", "event=frame_truncated len=%zu need=%zu",
                  len, expected_len);
        return -1;
    }

    u32 crc_net = h->crc;
    u32 crc_host = ntohl(crc_net);

    if (payload_size > 0)
        enc_dec(packet->payload, packet->payload, (const u8 *)&crc_net, payload_size);

    h->crc = 0;
    u32 crc_calc = csum32((const u8 *)packet, expected_len);
    h->crc = crc_net;

    if (crc_host != crc_calc) {
        log_error("packet", "event=crc_mismatch recv=%u calc=%u", crc_host, crc_calc);
        return -1;
    }

    if (payload_size > 0)
        enc_dec(packet->payload, packet->payload, zero_key, payload_size);

    return (int)payload_size;
}

void packet_dedup_init(packet_dedup_t *cache) {
    if (!cache) return;
    memset(cache, 0, sizeof(*cache));
}

static inline u64 timespec_to_ns(const struct timespec *ts) {
    return (u64)ts->tv_sec * NSEC_PER_SEC + (u64)ts->tv_nsec;
}

int packet_dedup_handler(packet_dedup_t *cache, const u8 mac[ETH_ALEN],
                             u32 crc, u32 payload_size, u32 signature,
                             u64 window_ns) {
    if (!cache || !mac) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64 now_ns = timespec_to_ns(&now);

    for (size_t i = 0; i < PACKET_DEDUP_CACHE; i++) {
        packet_fingerprint_t *entry = &cache->entries[i];
        if (!entry->valid) continue;
        u64 entry_ns = timespec_to_ns(&entry->ts);
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

void debug_dump_frame(const char *prefix, const u8 *data, size_t len) {
    if (!data || !len) return;

    const char *path = "logs/clientserver.log";
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);

    if (fd < 0) {
        log_error_errno("debug_dump", "open='%s'", path);
        return;
    }
    if (fchmod(fd, (mode_t)0666) < 0) {
        log_error_errno("debug_dump", "fchmod='%s'", path);
        close(fd);
        return;
    }

    FILE *log_file = fdopen(fd, "a");
    if (!log_file) {
        log_error_errno("debug_dump", "fdopen");
        close(fd);
        return;
    }

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

static void log_internal(const char *level, const char *tag, const char *fmt, va_list ap) {
    if (!level) level = "info";
    if (!tag) tag = "app";
    fprintf(stderr, "level=%s tag=%s ", level, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_info(const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal("info", tag, fmt, ap);
    va_end(ap);
}

void log_error_errno(const char *tag, const char *fmt, ...) {
    int err = errno;
    va_list ap;
    va_start(ap, fmt);
    char buf[256];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    log_error(tag, "errno=%d err='%s' %s", err, strerror(err), buf);
    va_end(ap);
}

void log_error(const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal("error", tag, fmt, ap);
    va_end(ap);
}

int init_packet_socket(int *sockfd, struct ifreq *ifr, struct sockaddr_ll *bind_addr, const char *iface, int bind_to_device) {
    if (!sockfd || !ifr || !bind_addr) return -1;

    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_CUSTOM));
    if (*sockfd < 0) {
        log_error_errno("packet_socket", "socket");
        return -1;
    }

    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0) {
        log_error_errno("packet_socket", "fcntl_get");
        deinit_packet_socket(sockfd);
        return -1;
    }
    if (fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error_errno("packet_socket", "fcntl_set");
        deinit_packet_socket(sockfd);
        return -1;
    }

    struct timeval tv = {.tv_sec = 1, .tv_usec = 500000};
    if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
        log_error_errno("packet_socket", "setsockopt_rcvtimeo");
        deinit_packet_socket(sockfd);
        return -1;
    }

    int ifindex = 0;
    if (iface && *iface) {
        if (bind_to_device) {
            if (setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface, strnlen(iface, IFNAMSIZ)) < 0) {
                log_error_errno("packet_socket", "bindtodevice");
                deinit_packet_socket(sockfd);
                return -1;
            }
        }

        ifindex = if_nametoindex(iface);
        if (!ifindex) {
            log_error_errno("packet_socket", "if_nametoindex");
            deinit_packet_socket(sockfd);
            return -1;
        }

        memset(ifr, 0, sizeof(*ifr));
        strncpy(ifr->ifr_name, iface, IFNAMSIZ - 1);
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(*sockfd, SIOCGIFHWADDR, ifr) < 0) {
            log_error_errno("packet_socket", "SIOCGIFHWADDR");
            deinit_packet_socket(sockfd);
            return -1;
        }
    } else {
        memset(ifr, 0, sizeof(*ifr));
    }

    memset(bind_addr, 0, sizeof(*bind_addr));
    bind_addr->sll_family = AF_PACKET;
    bind_addr->sll_protocol = htons(ETHER_TYPE_CUSTOM);
    bind_addr->sll_ifindex = ifindex;

    if (bind(*sockfd, (struct sockaddr *)bind_addr, sizeof(*bind_addr)) < 0) {
        log_error_errno("packet_socket", "bind");
        deinit_packet_socket(sockfd);
        return -1;
    }

    return 0;
}

void deinit_packet_socket(int *sockfd) {
    if (!sockfd || *sockfd < 0) return;
    close(*sockfd);
    *sockfd = -1;
}
