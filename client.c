/* client.c - Layer 2 shell client (positional with named flags)
 * usage: client [-e|--echo] [-h|--help] <iface> <server-mac> [shell] [cmd]
 */

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "cli_helper.h"
#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RESPONSE_TIMEOUT_NS (500ULL * NSEC_PER_MSEC)

typedef struct {
    const char *iface;
    const char *mac_str;
    const char *shell;
    const char *cmd;
    int local_echo;
} client_args_t;

typedef struct {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll bind_addr;
    struct sockaddr_ll saddr;
    u8 server_mac[ETH_ALEN];
    int local_echo;
} client_ctx_t;

// forward declarations
static void usage(const char *p);
static int client_ctx_init(client_ctx_t *ctx, const client_args_t *args);
static void client_ctx_deinit(client_ctx_t *ctx);

/* time helpers */
static u64 mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

/* parse mac aa:bb:cc:dd:ee:ff */
static inline int a2mac(const char *s, u8 mac[ETH_ALEN]) {
    u8 v[ETH_ALEN];
    if (!s) return -1;
    int n = sscanf(s, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    if (n != ETH_ALEN) return -1;
    memcpy(mac, v, ETH_ALEN);
    return 0;
}

static int init_client_sock(client_ctx_t *ctx, const char *iface) {
    if (!ctx || !iface) return -1;

    if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, iface, 1) != 0) {
        return -1;
    }

    memset(&ctx->saddr, 0, sizeof(ctx->saddr));
    ctx->saddr.sll_family = AF_PACKET;
    ctx->saddr.sll_protocol = htons(ETHER_TYPE_CUSTOM);
    ctx->saddr.sll_ifindex = ctx->bind_addr.sll_ifindex;
    ctx->saddr.sll_halen = ETH_ALEN;
    memcpy(ctx->saddr.sll_addr, ctx->server_mac, ETH_ALEN);

    return 0;
}

static void client_ctx_deinit(client_ctx_t *ctx) {
    if (!ctx) return;
    deinit_packet_socket(&ctx->sockfd);
}

static int client_ctx_init(client_ctx_t *ctx, const client_args_t *args) {
    if (!ctx || !args || !args->iface || !args->mac_str) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->sockfd = -1;
    ctx->local_echo = args->local_echo;

    if (a2mac(args->mac_str, ctx->server_mac) < 0) {
        fprintf(stderr, "error: invalid mac format: %s\n", args->mac_str);
        return -1;
    }

    if (init_client_sock(ctx, args->iface) != 0) {
        client_ctx_deinit(ctx);
        return -1;
    }
    return 0;
}

/* crlf normalize for stdin */
static void norm_in(u8 *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n')
            buf[i] = '\r';
}

static int recv_once_and_print(client_ctx_t *ctx) {
    pack_t pack;
    struct sockaddr_ll peer;
    socklen_t plen = sizeof(peer);
    ssize_t got = recvfrom(ctx->sockfd, &pack, sizeof(pack), 0, (struct sockaddr *)&peer, &plen);
    if (got < 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        perror("recvfrom");
        return -1;
    }
    if (got == 0) return 0;

    if (peer.sll_ifindex != ctx->bind_addr.sll_ifindex) return 0;

    int psz = parse_packet(&pack, got, SERVER_SIGNATURE);
    if (psz <= 0) return 0;

    if (memcmp(pack.header.eth_hdr.ether_shost, ctx->server_mac, ETH_ALEN) != 0) return 0;

    if (psz > 0) (void)write(STDOUT_FILENO, pack.payload, (size_t)psz);

    return 1;
}

static int client_prepare_packet(client_ctx_t *ctx, pack_t *packet, const void *payload, size_t payload_len) {
    u8 src_mac[ETH_ALEN];
    int frame_len;

    if (!ctx || !packet) return -1;
    if (payload_len > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: payload too long (%zu)\n", payload_len);
        return -1;
    }

    memset(packet, 0, sizeof(*packet));
    if (payload && payload_len)
        memcpy(packet->payload, payload, payload_len);

    memcpy(src_mac, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    frame_len = build_packet(packet, payload_len, src_mac, ctx->server_mac, CLIENT_SIGNATURE);
    if (frame_len < 0) {
        fprintf(stderr, "build_packet failed\n");
        return -1;
    }
    return frame_len;
}

static int client_flush_packet(client_ctx_t *ctx, const pack_t *packet, size_t frame_len) {
    if (!ctx || !packet) return -1;
    debug_dump_frame("debug: client tx frame", (const u8 *)packet, frame_len);
    if (sendto(ctx->sockfd, packet, frame_len, 0, (struct sockaddr *)&ctx->saddr, sizeof(ctx->saddr)) < 0) {
        perror("sendto");
        return -1;
    }
    return 0;
}

/* tx frame */
static int client_send_payload(client_ctx_t *ctx, const void *payload, size_t payload_len) {
    pack_t packet;
    int frame_len = client_prepare_packet(ctx, &packet, payload, payload_len);
    if (frame_len < 0) return -1;
    return client_flush_packet(ctx, &packet, (size_t)frame_len);
}

static int client_handle_socket_event(client_ctx_t *ctx) {
    int rc = recv_once_and_print(ctx);
    return (rc < 0) ? -1 : 0;
}

static int client_handle_stdin_event(client_ctx_t *ctx) {
    u8 ibuf[MAX_PAYLOAD_SIZE];
    ssize_t r = read(STDIN_FILENO, ibuf, sizeof(ibuf));
    if (r < 0) {
        if (errno == EINTR) return 0;
        perror("read");
        return -1;
    }
    if (r == 0) return 0;

    norm_in(ibuf, (size_t)r);
    if (ctx->local_echo)
        (void)write(STDOUT_FILENO, ibuf, (size_t)r);
    return client_send_payload(ctx, ibuf, (size_t)r);
}

/* wait first response until deadline using shared recv path */
static int wait_resp(client_ctx_t *ctx, u64 deadline_ns) {
    int seen = 0;
    for (;;) {
        u64 now = mono_ns();
        if (now >= deadline_ns)
            return seen ? 1 : 0;

        u64 rem = deadline_ns - now;
        struct timeval tv;
        tv.tv_sec = (time_t)(rem / NSEC_PER_SEC);
        tv.tv_usec = (suseconds_t)((rem % NSEC_PER_SEC) / NSEC_PER_USEC);
        if (tv.tv_usec >= 1000000)
            tv.tv_usec = 999999;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->sockfd, &rfds);

        int rc = select(ctx->sockfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            return -1;
        }
        if (rc == 0)
            return seen ? 1 : 0;

        if (FD_ISSET(ctx->sockfd, &rfds)) {
            int r = recv_once_and_print(ctx);
            if (r < 0) return -1;
            if (r > 0) seen = 1;
        }
    }
}

/* interactive loop using shared recv path */
static int client_loop(client_ctx_t *ctx) {
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx->sockfd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = ctx->sockfd > STDIN_FILENO ? ctx->sockfd : STDIN_FILENO;

        int rc = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            return -1;
        }

        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            if (client_handle_stdin_event(ctx) != 0)
                return -1;
        }

        if (FD_ISSET(ctx->sockfd, &rfds)) {
            if (client_handle_socket_event(ctx) != 0)
                return -1;
        }
    }
}

/* cli parser using cli_helper.h style */
static int parse_client_args(int argc, char **argv, client_args_t *args) {
    if (!args || !argv) return EINVAL;
    memset(args, 0, sizeof(*args));

    const char *argv0 = argv[0];

    while (argc > 1) {
        NEXT_ARG();
        if (matches(*argv, "-h") || matches(*argv, "--help")) {
            usage(argv0);
            return 1;
        }
        if (matches(*argv, "-e") || matches(*argv, "--echo")) {
            args->local_echo = 1;
            continue;
        }
        if (!args->iface) {
            args->iface = *argv;
            continue;
        }
        if (!args->mac_str) {
            args->mac_str = *argv;
            continue;
        }
        if (!args->shell) {
            args->shell = *argv;
            continue;
        }
        if (!args->cmd) {
            args->cmd = *argv;
            continue;
        }
        fprintf(stderr, "error: unexpected arg '%s'\n", *argv);
        return -1;
    }

    if (!args->iface || !args->mac_str) {
        usage(argv0);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    client_args_t a;
    int pr = parse_client_args(argc, argv, &a);
    if (pr != 0)
        return pr > 0 ? 0 : 1;

    client_ctx_t ctx;
    if (client_ctx_init(&ctx, &a) != 0)
        return 1;

    if (a.shell) {
        size_t slen = strlen(a.shell) + 1;
        if (client_send_payload(&ctx, a.shell, slen) != 0) {
            client_ctx_deinit(&ctx);
            return 1;
        }
    }

    if (a.cmd) {
        u8 buf[MAX_PAYLOAD_SIZE];
        size_t len = strlen(a.cmd);
        if (len + 1 > sizeof(buf)) {
            fprintf(stderr, "error: command too long\n");
            client_ctx_deinit(&ctx);
            return 1;
        }
        memcpy(buf, a.cmd, len);
        buf[len] = '\r'; /* many servers expect cr */
        if (ctx.local_echo) {
            (void)write(STDOUT_FILENO, buf, len);
            (void)write(STDOUT_FILENO, "\n", 1);
        }
        if (client_send_payload(&ctx, buf, len + 1) != 0) {
            client_ctx_deinit(&ctx);
            return 1;
        }

        u64 dl = mono_ns() + RESPONSE_TIMEOUT_NS;
        int seen = wait_resp(&ctx, dl);
        if (seen <= 0) {
            if (seen == 0)
                fprintf(stderr, "error: no response within timeout\n");
            client_ctx_deinit(&ctx);
            return 1;
        }
        client_ctx_deinit(&ctx);
        return 0;
    }

    {
        int rc = client_loop(&ctx);
        client_ctx_deinit(&ctx);
        return rc == 0 ? 0 : 1;
    }
}

/* usage printer */
static void usage(const char *p) {
    fprintf(stderr, "usage: %s [-e|--echo] [-h|--help] <iface> <server-mac> [shell] [cmd]\n", p);
}
