// server.c - L2 shell server implementation

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "cli_helper.h"
#include "common.h"
#include "frame_dedup.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h> // isspace
#include <errno.h> //EINTR MACRO
#include <fcntl.h> // Для функции fcntl
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h> //difftime
#include <unistd.h>

#define SERVER_IDLE_TIMEOUT_DEFAULT_SEC 30
#define SERVER_IDLE_TIMEOUT_MAX_SEC 600
#define DELAY_SEC 1
#define SERVER_DUP_RING 16
#define SERVER_DUP_WINDOW_NS (2ULL * NSEC_PER_MSEC)

int sh_fd = -1;
volatile sig_atomic_t pid = -1;
static frame_dedup_entry_t server_dedup_slots[SERVER_DUP_RING];
static frame_dedup_cache_t server_dedup = {
    .slots = server_dedup_slots,
    .capacity = SERVER_DUP_RING,
    .cursor = 0,
};

typedef struct server_ctx server_ctx_t;

static void start_shell_proc(const char *command);
static void terminate_shell_process(void);
static int server_exec(const u8 *payload, size_t payload_size);
static ssize_t write_all(int fd, const void *buf, size_t count);
static void check_shell_termination(void);
static void usage(const char *prog);
static u64 server_mono_ns(void);
static void server_format_ifname(int ifindex, char buf[IFNAMSIZ]);
static u32 server_frame_fingerprint(const pack_t *packet, size_t len);
static int server_frame_dedup_should_drop(const pack_t *packet, size_t len, const struct sockaddr_ll *peer);
static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload, size_t payload_size, const struct sockaddr_ll *peer);
static int server_hello_handler(server_ctx_t *ctx, const u8 *payload, size_t payload_size, const struct sockaddr_ll *peer);
static inline int server_timeout_to_ticks(int seconds);
static void server_apply_idle_timeout(server_ctx_t *ctx, int seconds);

typedef struct server_args {
    const char *iface;
    int any_iface;
    const char *log_path;
} server_args_t;

struct server_ctx {
    int sockfd;
    struct sockaddr_ll bind_addr;
    struct sockaddr_ll peer_addr;
    struct ifreq ifr;
    int any_iface;
    u64 pending_nonce;
    int awaiting_nonce_confirm;
    int idle_timeout_ticks;
};

static inline int server_timeout_to_ticks(int seconds) {
    int secs = seconds;
    if (secs <= 0)
        secs = 1;
    return (secs + DELAY_SEC - 1) / DELAY_SEC;
}

static void server_apply_idle_timeout(server_ctx_t *ctx, int seconds) {
    if (!ctx) return;
    int secs = seconds;
    if (secs <= 0)
        secs = SERVER_IDLE_TIMEOUT_DEFAULT_SEC;
    if (secs > SERVER_IDLE_TIMEOUT_MAX_SEC)
        secs = SERVER_IDLE_TIMEOUT_MAX_SEC;
    ctx->idle_timeout_ticks = server_timeout_to_ticks(secs);
}

static ssize_t write_all(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t remaining = count;
    ssize_t written = 0;

    while (remaining > 0) {
        written = write(fd, ptr, remaining);

        if (written < 0) {
            // Если произошла ошибка EINTR (прерывание системным вызовом),
            // продолжаем запись
            if (errno == EINTR) {
                continue;
            }
            // Для других ошибок возвращаем код ошибки
            return -1;
        }

        // Если write() вернул 0, это необычная ситуация
        if (written == 0) {
            return count - remaining;
        }

        // Обновляем указатель и оставшееся количество байт
        ptr += written;
        remaining -= written;
    }

    return count;
}

// Функция для обработки чтения данных от клиента и отправки их процессу сервера
static ssize_t server_read_raw_frame(server_ctx_t *ctx, pack_t *packet, struct sockaddr_ll *peer) {
    assert(ctx);
    assert(packet);
    assert(peer);
    if (ctx->sockfd < 0) return -1;

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    ssize_t ret = recvfrom(ctx->sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)peer, &saddr_len);
    debug_dump_frame("server_rx frame", (const u8 *)packet, (size_t)ret);
    return ret;
}

static int server_update_iface_out(server_ctx_t *ctx, const struct sockaddr_ll *peer) {
    if (!ctx || !peer) return -1;
    if (!ctx->any_iface) return 0;

    char name[IFNAMSIZ] = {0};
    if (!if_indextoname(peer->sll_ifindex, name)) {
        log_error_errno("server_iface", "if_indextoname");
        return -1;
    }

    struct ifreq tmp = {0};
    strncpy(tmp.ifr_name, name, IFNAMSIZ - 1);
    tmp.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(ctx->sockfd, SIOCGIFHWADDR, &tmp) < 0) {
        log_error_errno("server_iface", "SIOCGIFHWADDR");
        return -1;
    }
    memcpy(&ctx->ifr, &tmp, sizeof(tmp));
    ctx->bind_addr.sll_ifindex = peer->sll_ifindex;
    return 0;
}

static int server_validate_mac(server_ctx_t *ctx, const packh_t *header) {
    assert(ctx);
    assert(header);
    if (ctx->any_iface)
        return 0;
    if (memcmp(header->eth_hdr.ether_dhost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) != 0)
        return -1;
    if (memcmp(header->eth_hdr.ether_shost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) == 0)
        return -1;
    return 0;
}

static void server_send_ready_ack(server_ctx_t *ctx, const hello_view_t *hello) {
    char msg[128];
    size_t msg_len;
    pack_t packet;
    int frame_len;
    char ifname[IFNAMSIZ];

    if (!ctx || ctx->sockfd < 0 || !hello)
        return;

    if (hello->have_nonce) {
        msg_len = (size_t)snprintf(msg, sizeof(msg),
                                   "ready nonce=%016llx source=userland\n",
                                   (unsigned long long)hello->nonce);
    } else {
        msg_len = (size_t)snprintf(msg, sizeof(msg),
                                   "ready source=userland\n");
    }

    memcpy(packet.payload, msg, msg_len);

    frame_len = build_packet(&packet, msg_len,
                             (u8 *)ctx->ifr.ifr_hwaddr.sa_data,
                             (u8 *)ctx->peer_addr.sll_addr,
                             SERVER_SIGNATURE);
    if (frame_len < 0) {
        log_error("server_ready", "event=build_failed len=%zu", msg_len);
        return;
    }
    debug_dump_frame("server_tx ready ack frame", (const u8 *)&packet, (size_t)frame_len);
    server_format_ifname(ctx->bind_addr.sll_ifindex, ifname);

    if (sendto(ctx->sockfd, &packet, (size_t)frame_len, 0,
               (struct sockaddr *)&ctx->peer_addr, sizeof(ctx->peer_addr)) < 0) {
        log_error_errno("server_ready", "sendto");
    } else {
        log_info("server_ready", "event=sent nonce=%016llx has_nonce=%d iface=%s",
                 (unsigned long long)hello->nonce, hello->have_nonce, ifname);
    }
}

static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload, size_t payload_size, const struct sockaddr_ll *peer);

static int server_cmd_exec_handler(server_ctx_t *ctx, pack_t *packet, int payload_size, const struct sockaddr_ll *peer) {
    assert(ctx);
    assert(packet);

    if (peer) {
        ctx->peer_addr = *peer;
        if (ctx->any_iface)
            (void)server_update_iface_out(ctx, peer);
    }

    if (payload_size > 0) {
        hello_view_t hello = {0};
        if (hello_parse(packet->payload, (size_t)payload_size, &hello) == 0 && hello.shell_started && hello.cmd_len > 0) {
            if (hello.have_nonce) {
                ctx->pending_nonce = hello.nonce;
                ctx->awaiting_nonce_confirm = 1;
            } else {
                ctx->awaiting_nonce_confirm = 0;
            }
            if (hello.have_idle_timeout) {
                server_apply_idle_timeout(ctx, hello.idle_timeout_seconds);
            }
            if (server_exec(hello.cmd, hello.cmd_len) != 0) {
                log_error("server_launch", "event=hello_launch_failed");
            } else {
                server_send_ready_ack(ctx, &hello);
            }
            log_info("idle_timeout", "ticks=%d", ctx->idle_timeout_ticks);
            return payload_size;
        }
    }

    const u8 *cmd = packet->payload;
    size_t cmd_sz = (size_t)payload_size;
    if (cmd_sz == 0 || (cmd_sz > 0 && isspace(cmd[0]))) {
        static const u8 default_cmd[] = "sh";
        cmd = default_cmd;
        cmd_sz = sizeof(default_cmd) - 1;
    }
    if (server_exec(cmd, cmd_sz) != 0) {
        log_error("server_launch", "event=launch_failed");
    }
    return payload_size;
}

static int server_payload_handler(server_ctx_t *ctx, pack_t *packet, int payload_size, const struct sockaddr_ll *peer) {
    assert(ctx);
    assert(packet);
    if (server_nonce_confirm_handler(ctx, packet->payload, (size_t)payload_size, peer))
        return payload_size;
    if (sh_fd != -1 && server_hello_handler(ctx, packet->payload, (size_t)payload_size, peer))
        return payload_size;
    if (sh_fd == -1) return server_cmd_exec_handler(ctx, packet, payload_size, peer);
    (void)write_all(sh_fd, packet->payload, (size_t)payload_size);
    return payload_size;
}

static ssize_t server_socket_event_handler(server_ctx_t *ctx, pack_t *packet) {
    struct sockaddr_ll peer = {0};
    ssize_t ret = server_read_raw_frame(ctx, packet, &peer);
    if (ret <= 0) return ret;

    packh_t *header = (packh_t *)packet;
    int payload_size = -1;

    if (server_frame_dedup_should_drop(packet, (size_t)ret, &peer) != 0)
        return -1;

    char peer_ifname[IFNAMSIZ];
    server_format_ifname(peer.sll_ifindex, peer_ifname);

    if (server_validate_mac(ctx, header) != 0)
        return -1;

    u32 payload_size_host = ntohl(header->payload_size);
    u32 signature_host = ntohl(header->signature);
    u32 crc = ntohl(packet->header.crc);

    log_info("server_rx", "b=%zd ether=0x%04x pay_sz=%u src=" MACSTR " dst=" MACSTR " sign=0x%04x csum=%u iface=%s",
             ret,
             ntohs(header->eth_hdr.ether_type),
             payload_size_host,
             MAC2STR(header->eth_hdr.ether_shost),
             MAC2STR(header->eth_hdr.ether_dhost),
             signature_host,
             crc,
             peer_ifname);

    payload_size = parse_packet(packet, ret, CLIENT_SIGNATURE);
    if (payload_size < 0) {
        return payload_size;
    }

    return server_payload_handler(ctx, packet, payload_size, &peer);
}

static int server_exec(const u8 *payload, size_t payload_size) {
    if (payload_size == 0) {
        log_error("server_launch", "event=empty_payload");
        return -1;
    }
    static char command_buf[MAX_PAYLOAD_SIZE + 1];
    if (payload_size > sizeof(command_buf) - 1) {
        log_error("server_launch", "event=payload_overflow len=%zu", payload_size);
        return -1;
    }
    size_t writesz = MIN(sizeof(command_buf), payload_size); // limit the size to prevent overflow
    memcpy(command_buf, payload, writesz);
    command_buf[writesz] = '\0';
    if (command_buf[0] == '\0') {
        log_error("server_launch", "event=payload_null");
        return -1;
    }
    start_shell_proc(command_buf);
    return 0;
}

// Функция для обработки чтения и записи данных в клиент
static void server_handle_shell_event(server_ctx_t *ctx, pack_t *packet) {
    if (!ctx || ctx->sockfd < 0 || sh_fd < 0 || !packet) return;

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    ssize_t ret = read(sh_fd, packet->payload, MAX_PAYLOAD_SIZE);

    // Проверка успешности чтения из sh_fd
    if (ret <= 0) return; // Если чтение не удалось, выходим

    int packet_len = build_packet(packet, (size_t)ret, (u8 *)ctx->ifr.ifr_hwaddr.sa_data, (u8 *)ctx->peer_addr.sll_addr, SERVER_SIGNATURE);
    if (packet_len < 0) {
        return;
    }

    debug_dump_frame("server_tx frame", (const u8 *)&packet, (size_t)packet_len);
    ssize_t send_ret = sendto(ctx->sockfd, packet, (size_t)packet_len, 0, (struct sockaddr *)&ctx->peer_addr, saddr_len);
    char ifname[IFNAMSIZ];
    server_format_ifname(ctx->bind_addr.sll_ifindex, ifname);

    // Проверка успешности отправки
    if (send_ret < 0) {
        log_error_errno("server_tx", "sendto");
    } else {
        log_info("server_tx", "b=%zd ether=0x%04x pay_sz=%zu src=" MACSTR " dst=" MACSTR " sign=0x%04x csum=%u iface=%s",
                 send_ret,
                 ntohs(packet->header.eth_hdr.ether_type),
                 (size_t)ret,
                 MAC2STR(packet->header.eth_hdr.ether_shost),
                 MAC2STR(packet->header.eth_hdr.ether_dhost),
                 ntohl(packet->header.signature),
                 ntohl(packet->header.crc),
                 ifname);
    }
}

static void start_shell_proc(const char *command) {
    if (!command) {
        log_error("server_shell", "cmd=NULL");
        return;
    }
    pid_t child;
    log_info("server_shell", "forkpty execlp cmd='%s'", command);

    child = forkpty(&sh_fd, NULL, NULL, NULL);
    if (child < 0) {
        log_error_errno("server_shell", "forkpty");
        exit(1);
    }

    // child process
    if (child == 0) {
        log_info("server_shell", "execlp cmd='%s'", command);
        execlp(command, command, NULL);
        log_error_errno("server_shell", "execlp='%s'", command);
        _exit(1);
    }

    // parent process
    pid = child;
    log_info("server_shell", "started pid=%d cmd='%s'", (int)pid, command);
}

// Проверяет, завершился ли процесс команды, и очищает ресурсы
static void check_shell_termination(void) {
    sig_atomic_t current_pid = pid; // Атомарное чтение
    if (current_pid != -1) {
        int status;
        pid_t result = waitpid(current_pid, &status, WNOHANG);
        if (result == current_pid) {
            log_info("server_shell", "terminated pid=%d", current_pid);
            if (sh_fd != -1) {
                close(sh_fd);
                sh_fd = -1;
            }
            pid = -1;
            return;
        }
    }
}

static void terminate_shell_process(void) {
    sig_atomic_t current_pid = pid;

    if (current_pid != -1) {
        log_info("terminate forked process", "pid=%d", current_pid);
        if (kill(current_pid, SIGKILL) == -1 && errno != ESRCH) {
            log_error_errno("server_shell", "kill");
        }
        log_info("waitpid", "pid=%d", current_pid);
        if (waitpid(current_pid, NULL, 0) == -1 && errno != ECHILD) {
            log_error_errno("server_shell", "waitpid");
        }
        pid = -1;
    }

    if (sh_fd != -1) {
        log_info("close", "sh_fd=%d", sh_fd);
        close(sh_fd);
        sh_fd = -1;
    }
}

static int parse_server_args(int argc, char **argv, server_args_t *args) {
    if (!args || !argv) return 1;
    memset(args, 0, sizeof(*args));
    const char *argv0 = argv[0];

    while (argc > 1) {
        NEXT_ARG();
        if (matches(*argv, "-h") || matches(*argv, "--help")) {
            usage(argv0);
            return 1;
        }
        if (matches(*argv, "--log-file")) {
            NEXT_ARG();
            args->log_path = *argv;
            continue;
        }
        if (strcmp(*argv, "any") == 0) {
            args->any_iface = 1;
            args->iface = NULL;
            continue;
        }
        if (!args->iface) {
            args->iface = *argv;
            continue;
        }
        log_error("server_args", "event=unexpected_arg value=%s", *argv);
        return 1;
    }

    if (!args->iface && !args->any_iface) {
        usage(argv0);
        return 1;
    }
    return 0;
}

static int server_ctx_init(server_ctx_t *ctx, const server_args_t *args) {
    if (!ctx || !args) return -1;
    ctx->sockfd = -1;
    ctx->any_iface = args->any_iface;

    const char *listen_iface = args->any_iface ? NULL : args->iface;
    if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, listen_iface, 0) != 0) {
        return -1;
    }

    if (!ctx->any_iface) {
        u8 *mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data;
        log_info("server_ctx", "event=iface_ready mac=" MACSTR, MAC2STR((mac)));
    } else {
        log_info("server_ctx", "event=iface_ready any");
    }

    ctx->peer_addr = ctx->bind_addr;
    server_apply_idle_timeout(ctx, SERVER_IDLE_TIMEOUT_DEFAULT_SEC);
    return 0;
}

static void server_ctx_deinit(server_ctx_t *ctx) {
    log_info("server_ctx_deinit", "start");
    if (!ctx) return;
    deinit_packet_socket(&ctx->sockfd);
}

static int server_loop(server_ctx_t *ctx) {
    if (!ctx || ctx->sockfd < 0) return -1;

    fd_set fds;
    pack_t rx_packet = {0};
    pack_t tx_packet = {0};
    int idle_ticks = 0;

    while (1) {
        struct timeval tv = {.tv_sec = DELAY_SEC, .tv_usec = 0};
        FD_ZERO(&fds);
        FD_SET(ctx->sockfd, &fds);
        int max_fd = ctx->sockfd;

        if (sh_fd != -1) {
            FD_SET(sh_fd, &fds);
            if (sh_fd > max_fd) {
                max_fd = sh_fd;
            }
        }

        int ready = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error_errno("server_loop", "select");
            return -1;
        }

        check_shell_termination();

        int client_activity = 0;

        if (ready > 0) {
            if (FD_ISSET(ctx->sockfd, &fds)) {
                if (server_socket_event_handler(ctx, &rx_packet) >= 0) {
                    client_activity = 1;
                }
            }

            if (sh_fd != -1 && FD_ISSET(sh_fd, &fds)) {
                server_handle_shell_event(ctx, &tx_packet);
            }
        }

        if (client_activity) {
            idle_ticks = 0;
            continue;
        }

        idle_ticks++;
        if (idle_ticks > ctx->idle_timeout_ticks) {
            log_info("server_loop", "event=idle_timeout ticks=%d limit=%d",
                     idle_ticks, ctx->idle_timeout_ticks);
            terminate_shell_process();
            break;
        }
    }

    return 0;
}

int server_main(int argc, char *argv[]) {
    server_args_t args;
    server_ctx_t ctx;
    frame_dedup_reset(&server_dedup);

    int pr = parse_server_args(argc, argv, &args);
    if (pr != 0) return pr > 0 ? 0 : 1;
    if (args.log_path && log_redirect_stdio(args.log_path) != 0) {
        log_error_errno("server_args", "event=log_file_open path=%s", args.log_path);
        return 1;
    }

    if (server_ctx_init(&ctx, &args) != 0) {
        return 1;
    }

    int rc = server_loop(&ctx);
    server_ctx_deinit(&ctx);
    return (rc == 0) ? 0 : 1;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--log-file <path>] <interface|any> [--help]\n", prog);
}
static u64 server_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * NSEC_PER_SEC + (u64)ts.tv_nsec;
}

static void server_format_ifname(int ifindex, char buf[IFNAMSIZ]) {
    if (!buf) return;
    if (ifindex > 0 && if_indextoname((unsigned int)ifindex, buf))
        return;
    buf[0] = '?';
    buf[1] = '\0';
}

static u32 server_frame_fingerprint(const pack_t *packet, size_t len) {
    if (!packet || len < sizeof(packh_t))
        return 0;
    const packh_t *h = &packet->header;
    u32 crc = ntohl(h->crc);
    u32 sig = ntohl(h->signature);
    u32 psz = ntohl(h->payload_size);
    return crc ^ sig ^ psz;
}

// Проверяет, следует ли отбросить дубликат фрейма
static int server_frame_dedup_should_drop(const pack_t *packet, size_t len, const struct sockaddr_ll *peer) {
    if (!packet || len == 0)
        return 0;
    const u64 now = server_mono_ns();
    const u32 checksum = server_frame_fingerprint(packet, len);
    const int cur_ifindex = peer ? peer->sll_ifindex : 0;
    char cur_ifname[IFNAMSIZ];
    int prev_ifindex = 0;
    u64 age_ns = 0;

    server_format_ifname(cur_ifindex, cur_ifname);
    if (!frame_dedup_should_drop(&server_dedup,
                                 len,
                                 checksum,
                                 cur_ifindex,
                                 now,
                                 SERVER_DUP_WINDOW_NS,
                                 &prev_ifindex,
                                 &age_ns)) {
        return 0;
    }

    char prev_ifname[IFNAMSIZ];
    server_format_ifname(prev_ifindex, prev_ifname);
    log_info("server_dup",
             "event=drop len=%zu age_ns=%llu checksum=%u iface=%s prev_iface=%s",
             len,
             (unsigned long long)age_ns,
             checksum,
             cur_ifname,
             prev_ifname);
    return -1;
}

// обработчик подтверждения nonce от клиента
static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload, size_t payload_size, const struct sockaddr_ll *peer) {
    if (!ctx || !payload || payload_size == 0 || !ctx->awaiting_nonce_confirm)
        return 0;

    char buf[64];
    size_t copy = payload_size < sizeof(buf) - 1 ? payload_size : sizeof(buf) - 1;
    memcpy(buf, payload, copy);
    buf[copy] = '\0';

    unsigned long long tmp = 0;
    if (sscanf(buf, "nonce_confirm=%llx", &tmp) != 1)
        return 0;
    if ((u64)tmp != ctx->pending_nonce)
        return 0;

    ctx->awaiting_nonce_confirm = 0;
    if (peer) {
        ctx->peer_addr = *peer;
        if (ctx->any_iface)
            (void)server_update_iface_out(ctx, peer);
    }
    char ifname[IFNAMSIZ];
    server_format_ifname(peer ? peer->sll_ifindex : ctx->bind_addr.sll_ifindex, ifname);
    log_info("server_handshake", "event=nonce_confirmed nonce=%016llx iface=%s",
             (unsigned long long)ctx->pending_nonce, ifname);
    return 1;
}

static int server_hello_handler(server_ctx_t *ctx, const u8 *payload, size_t payload_size, const struct sockaddr_ll *peer) {
    if (!ctx || !payload || payload_size == 0)
        return 0;

    hello_view_t hello = {0};
    if (hello_parse(payload, payload_size, &hello) != 0 || !hello.shell_started)
        return 0;

    if (peer) {
        ctx->peer_addr = *peer;
        if (ctx->any_iface)
            (void)server_update_iface_out(ctx, peer);
    }

    if (hello.have_nonce) {
        ctx->pending_nonce = hello.nonce;
        ctx->awaiting_nonce_confirm = 1;
    } else {
        ctx->awaiting_nonce_confirm = 0;
    }

    server_send_ready_ack(ctx, &hello);
    log_info("server_hello", "event=resume shell_running=%d", sh_fd != -1 ? 1 : 0);
    return 1;
}
