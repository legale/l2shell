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
#include <assert.h>
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
#include <termios.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RESPONSE_TIMEOUT_NS (1000ULL * NSEC_PER_MSEC)
#define CLIENT_IDLE_TIMEOUT_DEFAULT_SEC 30

typedef struct {
    const char *iface;
    const char *mac_str;
    const char *spawn_cmd;
    const char *shell;
    const char *cmd;
    const char *log_path;
    int local_echo;
    int idle_timeout;
} client_args_t;

typedef struct {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll bind_addr;
    struct sockaddr_ll saddr;
    u8 server_mac[ETH_ALEN];
    int local_echo;
} client_ctx_t;

typedef struct ready_msg {
    u64 nonce;
    int have_nonce;
    int from_userland;
    int from_kernel;
} ready_msg_t;

static struct termios saved_stdin_termios;
static int stdin_raw_mode_enabled;

static void client_restore_stdin(void) {
    if (!stdin_raw_mode_enabled)
        return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_stdin_termios);
    stdin_raw_mode_enabled = 0;
}

static int client_enable_raw_mode(void) {
    struct termios raw;

    if (!isatty(STDIN_FILENO))
        return 0;

    if (tcgetattr(STDIN_FILENO, &saved_stdin_termios) < 0)
        return -1;

    raw = saved_stdin_termios;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0)
        return -1;

    stdin_raw_mode_enabled = 1;
    if (atexit(client_restore_stdin) != 0)
        client_restore_stdin();
    return 0;
}

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

static u64 client_generate_nonce(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((u64)ts.tv_sec << 32) ^ (u64)ts.tv_nsec ^ (u64)getpid();
}

static int parse_ready_message(const u8 *payload, size_t len, ready_msg_t *msg) {
    char buf[128];
    size_t copy;

    if (!payload || len == 0 || !msg)
        return 0;
    copy = len < sizeof(buf) - 1 ? len : sizeof(buf) - 1;
    memcpy(buf, payload, copy);
    buf[copy] = '\0';

    if (strncmp(buf, "ready", 5) != 0)
        return 0;

    msg->have_nonce = 0;
    msg->nonce = 0;
    msg->from_userland = 0;
    msg->from_kernel = 0;

    char *nonce_str = strstr(buf, "nonce=");
    if (nonce_str) {
        unsigned long long tmp;
        if (sscanf(nonce_str, "nonce=%llx", &tmp) == 1) {
            msg->have_nonce = 1;
            msg->nonce = (u64)tmp;
        }
    }
    char *source_str = strstr(buf, "source=");
    if (source_str) {
        if (strncmp(source_str, "source=userland", 15) == 0)
            msg->from_userland = 1;
        else if (strncmp(source_str, "source=kernel", 13) == 0)
            msg->from_kernel = 1;
    }
    return 1;
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
    assert(ctx);
    assert(iface);

    if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, iface, 0) != 0) {
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
        log_error("client_args", "event=invalid_mac value=%s", args->mac_str);
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

static int client_recv_packet(client_ctx_t *ctx, pack_t *pack, int *payload_len) {
    struct sockaddr_ll peer;
    socklen_t plen = sizeof(peer);
    ssize_t got;

    assert(ctx);
    assert(pack);

    got = recvfrom(ctx->sockfd, pack, sizeof(*pack), 0, (struct sockaddr *)&peer, &plen);
    if (got < 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        log_error_errno("client_recv", "recvfrom");
        return -1;
    }
    if (got == 0)
        return 0;
    if (peer.sll_ifindex != ctx->bind_addr.sll_ifindex)
        return 0;

    debug_dump_frame("client_rx frame ", (const u8 *)pack, got);

    int psz = parse_packet(pack, got, SERVER_SIGNATURE);
    if (psz <= 0)
        return 0;
    if (memcmp(pack->header.eth_hdr.ether_shost, ctx->server_mac, ETH_ALEN) != 0)
        return 0;
    if (payload_len)
        *payload_len = psz;
    return 1;
}

static int recv_once_and_print(client_ctx_t *ctx) {
    pack_t pack;
    int payload_len = 0;
    int rc = client_recv_packet(ctx, &pack, &payload_len);
    if (rc <= 0)
        return rc < 0 ? -1 : 0;
    if (payload_len > 0)
        (void)write(STDOUT_FILENO, pack.payload, (size_t)payload_len);
    return 1;
}

static int client_prepare_packet(client_ctx_t *ctx, pack_t *packet, const void *payload, size_t payload_len) {
    u8 src_mac[ETH_ALEN];
    int frame_len;

    assert(ctx);
    assert(packet);
    if (payload_len > MAX_DATA_SIZE) {
        log_error("client_packet", "event=payload_too_long len=%zu", payload_len);
        return -1;
    }

    memset(packet, 0, sizeof(*packet));
    if (payload && payload_len)
        memcpy(packet->payload, payload, payload_len);

    memcpy(src_mac, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    frame_len = build_packet(packet, payload_len, src_mac, ctx->server_mac, CLIENT_SIGNATURE);
    if (frame_len < 0) {
        log_error("client_packet", "event=build_packet_failed");
        return -1;
    }
    return frame_len;
}

static int client_flush_packet(client_ctx_t *ctx, const pack_t *packet, size_t frame_len) {
    assert(ctx);
    assert(packet);
    debug_dump_frame("client_tx frame ", (const u8 *)packet, frame_len);
    if (sendto(ctx->sockfd, packet, frame_len, 0, (struct sockaddr *)&ctx->saddr, sizeof(ctx->saddr)) < 0) {
        log_error_errno("client_send", "sendto");
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

static int client_send_nonce_confirm(client_ctx_t *ctx, u64 nonce) {
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "nonce_confirm=%016llx\n", (unsigned long long)nonce);
    if (len <= 0 || len >= (int)sizeof(buf)) {
        log_error("client_nonce", "event=format_failed");
        return -1;
    }
    return client_send_payload(ctx, buf, (size_t)len);
}

static int client_send_hello(client_ctx_t *ctx, const client_args_t *args, u64 *nonce_out) {
    const char *shell_cmd = (args && args->shell) ? args->shell : "sh";
    const char *spawn_cmd = NULL;
    int include_spawn = 0;
    if (args && args->spawn_cmd && args->spawn_cmd[0] != '\0') {
        spawn_cmd = args->spawn_cmd;
        include_spawn = 1;
    }
    u8 payload[MAX_DATA_SIZE] = {0};
    u64 nonce = client_generate_nonce();
    int timeout = CLIENT_IDLE_TIMEOUT_DEFAULT_SEC;
    if (args && args->idle_timeout > 0)
        timeout = args->idle_timeout;
    hello_builder_t builder = {
        .spawn_cmd = spawn_cmd,
        .shell_cmd = shell_cmd,
        .nonce = nonce,
        .include_spawn = include_spawn,
        .include_nonce = 1,
        .include_idle_timeout = 1,
        .idle_timeout_seconds = timeout,
    };
    int hello_len = hello_build(payload, sizeof(payload), &builder);
    if (hello_len < 0) {
        log_error("client_hello", "event=build_failed");
        return -1;
    }
    if (nonce_out)
        *nonce_out = nonce;
    return client_send_payload(ctx, payload, (size_t)hello_len);
}

static int client_wait_ready(client_ctx_t *ctx, u64 expected_nonce, u64 timeout_ns) {
    u64 deadline = mono_ns() + timeout_ns;
    pack_t pack;

    while (1) {
        u64 now = mono_ns();
        if (now >= deadline)
            return 1;

        u64 rem = deadline - now;
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
            log_error_errno("client_wait_ready", "select");
            return -1;
        }
        if (rc == 0)
            continue;

        if (FD_ISSET(ctx->sockfd, &rfds)) {
            ready_msg_t ready;
            int payload_len = 0;
            int got = client_recv_packet(ctx, &pack, &payload_len);
            if (got < 0)
                return -1;
            if (got == 0)
                continue;

            if (parse_ready_message(pack.payload, (size_t)payload_len, &ready)) {
                if (ready.have_nonce && ready.nonce == expected_nonce) {
                    if (ready.from_userland)
                        return 0;
                    if (ready.from_kernel)
                        return 2;
                }
                log_info("client_wait_ready",
                         "event=ready_ignored expected=%016llx recv=%016llx has_nonce=%d src=userland:%d kernel:%d",
                         (unsigned long long)expected_nonce,
                         (unsigned long long)ready.nonce,
                         ready.have_nonce,
                         ready.from_userland,
                         ready.from_kernel);
                continue;
            }

            /* non-ready payload during handshake, ignore */
        }
    }
}

static int client_handshake(client_ctx_t *ctx, const client_args_t *args) {
    const int max_attempts = 5;
    int attempt = 0;

    while (attempt < max_attempts) {
        u64 nonce = 0;
        if (client_send_hello(ctx, args, &nonce) != 0)
            return -1;
        int ready = client_wait_ready(ctx, nonce, RESPONSE_TIMEOUT_NS);
        if (ready == 0) {
            if (client_send_nonce_confirm(ctx, nonce) != 0)
                return -1;
            return 0;
        }
        if (ready == 2) {
            log_info("client_handshake", "event=kernel_ack nonce=%016llx", (unsigned long long)nonce);
            attempt++;
            continue;
        }
        if (ready < 0)
            return -1;
        log_error("client_handshake", "event=timeout attempt=%d", attempt + 1);
        attempt++;
    }

    log_error("client_handshake", "event=ready_failed attempts=%d", max_attempts);
    return -1;
}
static int client_handle_socket_event(client_ctx_t *ctx) {
    assert(ctx);
    int rc = recv_once_and_print(ctx);
    return (rc < 0) ? -1 : 0;
}

static int client_handle_stdin_event(client_ctx_t *ctx) {
    assert(ctx);
    u8 ibuf[MAX_DATA_SIZE];
    ssize_t r = read(STDIN_FILENO, ibuf, sizeof(ibuf));
    if (r < 0) {
        if (errno == EINTR) return 0;
        log_error_errno("client_stdin", "read");
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
            log_error_errno("client_wait", "select");
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
            log_error_errno("client_loop", "select");
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
static int parse_idle_timeout_value(const char *arg, int *value) {
    if (!arg || !value) return -1;
    char *endptr = NULL;
    long parsed = strtol(arg, &endptr, 10);
    if (!endptr || *endptr != '\0') return -1;
    if (parsed <= 0 || parsed > INT_MAX) return -1;
    *value = (int)parsed;
    return 0;
}

static int parse_client_args(int argc, char **argv, client_args_t *args) {
    if (!args || !argv) return 1;
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
        if (matches(*argv, "--spawn")) {
            NEXT_ARG();
            args->spawn_cmd = *argv;
            continue;
        }
        if (matches(*argv, "--idle-timeout")) {
            NEXT_ARG();
            int value = 0;
            if (parse_idle_timeout_value(*argv, &value) != 0) {
                log_error("client_args", "event=invalid_timeout value=%s", *argv);
                return 1;
            }
            args->idle_timeout = value;
            continue;
        }
        if (matches(*argv, "--log-file")) {
            NEXT_ARG();
            args->log_path = *argv;
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
        log_error("client_args", "event=unexpected_arg value=%s", *argv);
        return 1;
    }

    if (!args->iface || !args->mac_str) {
        usage(argv0);
        return 1;
    }
    return 0;
}

int client_main(int argc, char **argv) {
    client_args_t a = {0};
    int pr = parse_client_args(argc, argv, &a);
    if (pr != 0) return pr > 0 ? 0 : 1;
    if (a.idle_timeout <= 0)
        a.idle_timeout = CLIENT_IDLE_TIMEOUT_DEFAULT_SEC;
    if (a.log_path && log_redirect_stdio(a.log_path) != 0) {
        log_error_errno("client_args", "event=log_file_open path=%s", a.log_path);
        return 1;
    }

    client_ctx_t ctx;
    if (client_ctx_init(&ctx, &a) != 0)
        return 1;

    const int interactive = (a.cmd == NULL);
    if (interactive && client_enable_raw_mode() != 0) {
        log_error_errno("client_tty", "event=raw_mode");
    }

    if (client_handshake(&ctx, &a) != 0) {
        client_ctx_deinit(&ctx);
        if (interactive)
            client_restore_stdin();
        return 1;
    }

    if (a.cmd) {
        u8 buf[MAX_DATA_SIZE];
        size_t len = strlen(a.cmd);
        if (len + 2 > sizeof(buf)) {
            log_error("client_cmd", "event=command_too_long len=%zu", len);
            client_ctx_deinit(&ctx);
            return 1;
        }
        memcpy(buf, a.cmd, len);
        buf[len] = '\r';
        buf[len + 1] = '\n';
        if (ctx.local_echo) {
            (void)write(STDOUT_FILENO, buf, len);
            (void)write(STDOUT_FILENO, "\n", 1);
        }
        if (client_send_payload(&ctx, buf, len + 2) != 0) {
            client_ctx_deinit(&ctx);
            if (interactive)
                client_restore_stdin();
            return 1;
        }

        u64 dl = mono_ns() + RESPONSE_TIMEOUT_NS;
        int seen = wait_resp(&ctx, dl);
        if (seen <= 0) {
            if (seen == 0)
                log_error("client_wait", "event=no_response timeout_ns=%llu", (unsigned long long)RESPONSE_TIMEOUT_NS);
            client_ctx_deinit(&ctx);
            if (interactive)
                client_restore_stdin();
            return 1;
        }
        client_ctx_deinit(&ctx);
        if (interactive)
            client_restore_stdin();
        return 0;
    }

    {
        int rc = client_loop(&ctx);
        client_ctx_deinit(&ctx);
        if (interactive)
            client_restore_stdin();
        return rc == 0 ? 0 : 1;
    }
}

/* usage printer */
static void usage(const char *p) {
    fprintf(stderr, "usage: %s [-e|--echo] [--spawn <cmd>] [--idle-timeout <sec>] [--log-file <path>] [-h|--help] <iface> <server-mac> [shell] [cmd]\n", p);
}
