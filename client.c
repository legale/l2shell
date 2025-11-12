// client.c - Layer 2 shell client
//
// Power-of-Ten friendly refactor:
//  * No dynamic feature toggles in hot paths; state is explicit and local.
//  * Every loop has a clear termination condition.
//  * Functions stay under one page and have straightforward control flow.

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define COMMAND_RESPONSE_TIMEOUT_NS (1500ULL * NSEC_PER_MSEC)

typedef struct client_ctx {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll saddr;
    unsigned char server_mac[ETH_ALEN];
    int server_mac_known;
    int tty_fd;
    int tty_saved;
    struct termios tty_orig;
    int local_echo;
    int interactive_enabled;
    int send_command_mode;
    const char *one_shot_command;
    uint64_t command_deadline_ns;
    int response_seen;
    packet_dedup_t rx_dedup;
} client_ctx_t;

static unsigned char dst_mac[ETH_ALEN];

static void restore_tty(client_ctx_t *ctx) {
    if (!ctx->tty_saved) return;
    if (ctx->tty_fd >= 0 && tcsetattr(ctx->tty_fd, TCSANOW, &ctx->tty_orig) == -1) {
        perror("tcsetattr");
    }
    if (ctx->tty_fd > 0 && ctx->tty_fd != STDIN_FILENO) {
        close(ctx->tty_fd);
    }
    ctx->tty_fd = -1;
    ctx->tty_saved = 0;
}

static int acquire_tty(client_ctx_t *ctx) {
    if (ctx->tty_fd >= 0) return ctx->tty_fd;
    if (isatty(STDIN_FILENO)) {
        ctx->tty_fd = STDIN_FILENO;
    } else {
        ctx->tty_fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
        if (ctx->tty_fd < 0) {
            perror("open /dev/tty");
            return -1;
        }
    }
    if (!ctx->tty_saved) {
        if (tcgetattr(ctx->tty_fd, &ctx->tty_orig) == -1) {
            perror("tcgetattr");
            return -1;
        }
        ctx->tty_saved = 1;
    }
    return ctx->tty_fd;
}

static void set_raw_mode(client_ctx_t *ctx) {
    int fd = acquire_tty(ctx);
    if (fd < 0) {
        ctx->interactive_enabled = 0;
        fprintf(stderr, "warning: interactive input unavailable (no TTY)\n");
        return;
    }
    struct termios raw = ctx->tty_orig;
    cfmakeraw(&raw);
    raw.c_lflag |= ISIG;
    if (ctx->local_echo) {
        raw.c_lflag |= (ECHO | ECHONL | ECHOE | ECHOK);
    } else {
        raw.c_lflag &= ~(ECHO | ECHONL | ECHOE | ECHOK | ECHOCTL | ECHOKE);
    }
    if (tcsetattr(fd, TCSAFLUSH, &raw) == -1) {
        perror("tcsetattr");
        ctx->interactive_enabled = 0;
    }
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int init_socket(client_ctx_t *ctx, const char *iface) {
    memset(&ctx->ifr, 0, sizeof(ctx->ifr));
    strncpy(ctx->ifr.ifr_name, iface, IFNAMSIZ - 1);

    ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sockfd < 0) {
        perror("socket");
        return -1;
    }

    if (ioctl(ctx->sockfd, SIOCGIFHWADDR, &ctx->ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return -1;
    }

    int ifindex = if_nametoindex(iface);
    if (!ifindex) {
        perror("if_nametoindex");
        return -1;
    }

    memset(&ctx->saddr, 0, sizeof(ctx->saddr));
    ctx->saddr.sll_ifindex = ifindex;
    ctx->saddr.sll_halen = ETH_ALEN;

    struct timeval tv = {.tv_sec = 1, .tv_usec = 150000};
    setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    return 0;
}

// Отправка пакета с заданным MAC-адресом назначения
static int send_packet(client_ctx_t *ctx, pack_t *packet, size_t payload_len, const unsigned char *dst_mac) {
    uint8_t src_mac[ETH_ALEN];
    memcpy(src_mac, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ctx->saddr.sll_family = AF_PACKET;
    memcpy(ctx->saddr.sll_addr, dst_mac, ETH_ALEN);

    int frame_len = build_packet(packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    if (frame_len < 0) {
        fprintf(stderr, "build_packet failed\n");
        return -1;
    }

    debug_dump_frame("debug: client tx frame", (const uint8_t *)packet, (size_t)frame_len);

    if (sendto(ctx->sockfd, packet, (size_t)frame_len, 0, (struct sockaddr *)&ctx->saddr, sizeof(ctx->saddr)) < 0) {
        perror("sendto");
        return -1;
    }
    return 0;
}
// Отправка начального кадра с удаленной командой
static int send_init_frame(client_ctx_t *ctx, const char *remote_cmd) {
    pack_t packet = {0};
    size_t cmd_len = strlen(remote_cmd) + 1;
    if (cmd_len > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: remote command too long (%zu)\n", cmd_len);
        return -1;
    }
    memcpy(packet.payload, remote_cmd, cmd_len);
    const unsigned char *dst = ctx->server_mac_known ? ctx->server_mac : broadcast_mac;
    return send_packet(ctx, &packet, cmd_len, dst);
}

// Нормализация CR → LF в буфере
static void normalize_cr(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] == '\r') buf[i] = '\n';
    }
}

// Обработка ввода с TTY или stdin
static void handle_stdin(client_ctx_t *ctx) {
    pack_t packet = {0};
    ssize_t rd = read(ctx->tty_fd >= 0 ? ctx->tty_fd : STDIN_FILENO, packet.payload, MAX_PAYLOAD_SIZE);
    if (rd <= 0) return;
    if (!ctx->server_mac_known) {
        fprintf(stderr, "warning: server MAC unknown, dropping input\n");
        return;
    }
    normalize_cr(packet.payload, (size_t)rd);
    send_packet(ctx, &packet, (size_t)rd, ctx->server_mac);
}

// Печать MAC-адреса сервера при его первом получении
static void print_server_mac(const unsigned char *mac) {
    printf("server mac saved: ");
    for (int i = 0; i < ETH_ALEN; ++i) {
        printf("%02x", mac[i]);
        if (i != ETH_ALEN - 1) printf(":");
    }
    printf("\n");
}

// Обработка входящего пакета
static void handle_socket_rx(client_ctx_t *ctx) {
    pack_t packet = {0};
    struct sockaddr_ll peer = {0};
    socklen_t peer_len = sizeof(peer);
    ssize_t ret = recvfrom(ctx->sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&peer, &peer_len);
    if (ret <= 0) return;

    int payload_size = parse_packet(&packet, ret, SERVER_SIGNATURE);
    if (payload_size < 0) {
        return;
    }

    packh_t *hdr = &packet.header;
    uint32_t crc_host = ntohl(hdr->crc);
    if (packet_dedup_should_drop(&ctx->rx_dedup,
                                 (uint8_t *)hdr->eth_hdr.ether_shost,
                                 crc_host,
                                 (uint32_t)payload_size,
                                 ntohl(hdr->signature),
                                 PACKET_DEDUP_WINDOW_NS)) {
        return;
    }

    if (!ctx->server_mac_known ||
        memcmp(ctx->server_mac, hdr->eth_hdr.ether_shost, ETH_ALEN) != 0) {
        memcpy(ctx->server_mac, hdr->eth_hdr.ether_shost, ETH_ALEN);
        ctx->server_mac_known = 1;
        print_server_mac(ctx->server_mac);
    }

    if (payload_size > 0) {
        write(STDOUT_FILENO, packet.payload, (size_t)payload_size);
    }

    if (ctx->send_command_mode && payload_size > 0) {
        ctx->response_seen = 1;
        ctx->command_deadline_ns = monotonic_ns() + COMMAND_RESPONSE_TIMEOUT_NS;
    }
}

// Основной цикл обработки событий
static void pump_events(client_ctx_t *ctx) {
    fd_set readfds;
    pack_t packet = {0};
    pack_t packet2 = {0};
    (void)packet;
    (void)packet2;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(ctx->sockfd, &readfds);
        int max_fd = ctx->sockfd;
        if (ctx->interactive_enabled) {
            FD_SET(ctx->tty_fd >= 0 ? ctx->tty_fd : STDIN_FILENO, &readfds);
            if ((ctx->tty_fd >= 0 ? ctx->tty_fd : STDIN_FILENO) > max_fd) {
                max_fd = ctx->tty_fd >= 0 ? ctx->tty_fd : STDIN_FILENO;
            }
        }

        struct timeval tv;
        struct timeval *tv_ptr = NULL;
        if (ctx->send_command_mode) {
            uint64_t now = monotonic_ns();
            if (now >= ctx->command_deadline_ns) {
                break;
            }
            uint64_t remaining = ctx->command_deadline_ns - now;
            if (remaining > (uint64_t)INT_MAX * NSEC_PER_SEC) {
                remaining = (uint64_t)INT_MAX * NSEC_PER_SEC;
            }
            tv.tv_sec = (time_t)(remaining / NSEC_PER_SEC);
            tv.tv_usec = (suseconds_t)((remaining % NSEC_PER_SEC) / NSEC_PER_USEC);
            if (tv.tv_usec >= 1000000) tv.tv_usec = 999999;
            tv_ptr = &tv;
        }

        int ready = select(max_fd + 1, &readfds, NULL, NULL, tv_ptr);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            continue;
        }

        if (ctx->interactive_enabled &&
            FD_ISSET(ctx->tty_fd >= 0 ? ctx->tty_fd : STDIN_FILENO, &readfds)) {
            handle_stdin(ctx);
        }

        if (FD_ISSET(ctx->sockfd, &readfds)) {
            handle_socket_rx(ctx);
        }

        if (ctx->send_command_mode) {
            if (ctx->response_seen) continue;
            if (ready == 0) break;
        }
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <iface> <server-mac> <remote-shell> [command] [--local-echo]\n"
            "       %s --tty-loop [--local-echo]\n",
            prog, prog);
}

//
int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    client_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.sockfd = -1;
    ctx.tty_fd = -1;

    const char *iface = NULL;
    const char *mac_str = NULL;
    const char *remote_cmd = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--local-echo") == 0) {
            ctx.local_echo = 1;
        } else if (strcmp(argv[i], "--tty-loop") == 0) {
            ctx.interactive_enabled = 1;
            set_raw_mode(&ctx);
            unsigned char buf[256];
            while (1) {
                ssize_t rd = read(ctx.tty_fd >= 0 ? ctx.tty_fd : STDIN_FILENO, buf, sizeof(buf));
                if (rd <= 0) break;
                if (write(STDOUT_FILENO, buf, rd) < 0) break;
            }
            restore_tty(&ctx);
            return 0;
        } else if (!iface) {
            iface = argv[i];
        } else if (!mac_str) {
            mac_str = argv[i];
        } else if (!remote_cmd) {
            remote_cmd = argv[i];
        } else if (!ctx.one_shot_command) {
            ctx.one_shot_command = argv[i];
            ctx.send_command_mode = 1;
        } else {
            fprintf(stderr, "error: unexpected argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!iface || !mac_str || !remote_cmd) {
        usage(argv[0]);
        return 1;
    }

    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2],
               &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "error: invalid mac format: %s\n", mac_str);
        return 1;
    }
    memcpy(ctx.server_mac, dst_mac, ETH_ALEN);
    ctx.server_mac_known = 1;

    packet_dedup_init(&ctx.rx_dedup);
    ctx.interactive_enabled = !ctx.send_command_mode;
    ctx.response_seen = 0;
    ctx.command_deadline_ns = 0;

    if (init_socket(&ctx, iface) != 0) {
        restore_tty(&ctx);
        return 1;
    }

    set_raw_mode(&ctx);
    if (send_init_frame(&ctx, remote_cmd) != 0) {
        restore_tty(&ctx);
        return 1;
    }
    printf("Sending initial packet to: %s\r\n", mac_str);

    if (ctx.send_command_mode) {
        pack_t packet = {0};
        if (ctx.one_shot_command) {
            size_t cmd_len = strlen(ctx.one_shot_command);
            size_t payload_len = cmd_len + 1;
            if (payload_len > MAX_PAYLOAD_SIZE) {
                fprintf(stderr, "error: command too long\n");
                restore_tty(&ctx);
                return 1;
            }
            memcpy(packet.payload, ctx.one_shot_command, cmd_len);
            packet.payload[cmd_len] = '\r';
            normalize_cr(packet.payload, payload_len);
            if (send_packet(&ctx, &packet, payload_len, ctx.server_mac) != 0) {
                restore_tty(&ctx);
                return 1;
            }
            ctx.command_deadline_ns = monotonic_ns() + COMMAND_RESPONSE_TIMEOUT_NS;
        }
    }

    pump_events(&ctx);

    if (ctx.send_command_mode && !ctx.response_seen) {
        fprintf(stderr, "error: no response within timeout\n");
        restore_tty(&ctx);
        return 1;
    }

    restore_tty(&ctx);
    close(ctx.sockfd);
    return 0;
}
