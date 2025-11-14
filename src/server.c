// server.c - L2 shell server implementation

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

#define TIMEOUT 10
#define SERVER_IDLE_TICKS 10

int sh_fd = -1;
volatile sig_atomic_t pid = -1;
static packet_dedup_t server_rx_dedup;

static void start_command_process(const char *command);
static void terminate_shell_process(void);
static int launch_remote_command(const u8 *payload, size_t payload_size);
static ssize_t write_all(int fd, const void *buf, size_t count);
static void check_command_termination(void);
static void usage(const char *prog);

typedef struct server_args {
    const char *iface;
} server_args_t;

typedef struct server_ctx {
    int sockfd;
    struct sockaddr_ll bind_addr;
    struct sockaddr_ll peer_addr;
    struct ifreq ifr;
} server_ctx_t;

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

// Функция для обработки чтения данных от клиента и отправки их в команду
static ssize_t server_read_raw_frame(server_ctx_t *ctx, pack_t *packet, struct sockaddr_ll *peer) {
    assert(ctx);
    assert(packet);
    assert(peer);
    if (ctx->sockfd < 0) return -1;

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    ssize_t ret = recvfrom(ctx->sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)peer, &saddr_len);
    debug_dump_frame("debug: server rx frame", (const u8 *)packet, (size_t)ret);
    return ret;
}

static int server_validate_mac(server_ctx_t *ctx, const packh_t *header) {
    assert(ctx);
    assert(header);
    if (memcmp(header->eth_hdr.ether_dhost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) != 0)
        return -1;
    if (memcmp(header->eth_hdr.ether_shost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) == 0)
        return -1;
    return 0;
}

static int server_check_duplicate(const packh_t *header, u32 payload_size_host, u32 signature_host) {
    if (packet_dedup_should_drop(&server_rx_dedup,
                                 (const u8 *)header->eth_hdr.ether_shost,
                                 ntohl(header->crc),
                                 payload_size_host,
                                 signature_host,
                                 PACKET_DEDUP_WINDOW_NS)) {
        return -1;
    }
    return 0;
}

static void server_send_ready_ack(server_ctx_t *ctx, const hello_view_t *hello) {
    char msg[128];
    size_t msg_len;
    pack_t packet;
    int frame_len;

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
    if (sendto(ctx->sockfd, &packet, (size_t)frame_len, 0,
               (struct sockaddr *)&ctx->peer_addr, sizeof(ctx->peer_addr)) < 0) {
        log_error_errno("server_ready", "sendto");
    } else {
        log_info("server_ready", "event=sent nonce=%016llx has_nonce=%d",
                 (unsigned long long)hello->nonce, hello->have_nonce);
    }
}

static int server_handle_command_launch(server_ctx_t *ctx, pack_t *packet, int payload_size) {
    assert(ctx);
    assert(packet);

    if (payload_size > 0) {
        hello_view_t hello = {0};
        if (hello_parse(packet->payload, (size_t)payload_size, &hello) == 0 && hello.have_shell && hello.shell_len > 0) {
            if (launch_remote_command(hello.shell_cmd, hello.shell_len) != 0) {
                log_error("server_launch", "event=hello_launch_failed");
            } else {
                server_send_ready_ack(ctx, &hello);
            }
            return payload_size;
        }
    }

    const u8 *cmd_payload = packet->payload;
    size_t cmd_size = (size_t)payload_size;
    if (cmd_size == 0 || (cmd_size == 1 && packet->payload[0] == '\n')) {
        static const u8 default_cmd[] = "sh";
        cmd_payload = default_cmd;
        cmd_size = sizeof(default_cmd) - 1;
    }
    if (launch_remote_command(cmd_payload, cmd_size) != 0) {
        log_error("server_launch", "event=launch_failed");
    }
    return payload_size;
}

static int server_dispatch_payload(server_ctx_t *ctx, pack_t *packet, int payload_size) {
    assert(ctx);
    assert(packet);
    if (sh_fd == -1) return server_handle_command_launch(ctx, packet, payload_size);
    (void)write_all(sh_fd, packet->payload, (size_t)payload_size);
    return payload_size;
}

static ssize_t server_handle_socket_event(server_ctx_t *ctx, pack_t *packet) {
    struct sockaddr_ll peer = {0};
    ssize_t ret = server_read_raw_frame(ctx, packet, &peer);
    if (ret <= 0) return ret;

    packh_t *header = (packh_t *)packet;
    int payload_size = -1;

    if (server_validate_mac(ctx, header) != 0)
        return -1;

    u32 payload_size_host = ntohl(header->payload_size);
    u32 signature_host = ntohl(header->signature);
    u32 crc = ntohl(packet->header.crc);

    log_info("server_rx", "b=%zd ether=0x%04x pay_sz=%u src=" MACSTR " dst=" MACSTR " sign=0x%04x csum=%u",
             ret,
             ntohs(header->eth_hdr.ether_type),
             payload_size_host,
             MAC2STR(header->eth_hdr.ether_shost),
             MAC2STR(header->eth_hdr.ether_dhost),
             signature_host,
             crc);

    if (server_check_duplicate(header, payload_size_host, signature_host) != 0) {
        return -1;
    }

    // Копируем saddr, поскольку это правильный отправитель
    ctx->peer_addr = peer;

    payload_size = parse_packet(packet, ret, CLIENT_SIGNATURE);
    if (payload_size < 0) {
        return payload_size;
    }

    return server_dispatch_payload(ctx, packet, payload_size);
}

static int launch_remote_command(const u8 *payload, size_t payload_size) {
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
    command_buf[payload_size] = '\0';
    if (command_buf[0] == '\0') {
        log_error("server_launch", "event=payload_null");
        return -1;
    }
    start_command_process(command_buf);
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

    ssize_t send_ret = sendto(ctx->sockfd, packet, (size_t)packet_len, 0, (struct sockaddr *)&ctx->peer_addr, saddr_len);

    // Проверка успешности отправки
    if (send_ret < 0) {
        log_error_errno("server_tx", "sendto");
    } else {
        log_info("server_tx", "b=%zd ether=0x%04x pay_sz=%zu src=" MACSTR " dst=" MACSTR " sign=0x%04x csum=%u",
                 send_ret,
                 ntohs(packet->header.eth_hdr.ether_type),
                 (size_t)ret,
                 MAC2STR(packet->header.eth_hdr.ether_shost),
                 MAC2STR(packet->header.eth_hdr.ether_dhost),
                 ntohl(packet->header.signature),
                 ntohl(packet->header.crc));
    }
}

static void start_command_process(const char *command) {
    pid = forkpty(&sh_fd, NULL, NULL, NULL);
    if (pid == 0) {
        execlp(command, command, NULL);
        log_error_errno("server_shell", "execlp");
        exit(1);
    }
    if (pid < 0) {
        log_error_errno("server_shell", "forkpty");
        exit(1);
    }
    log_info("server_shell started", "pid=%d", pid);
}

// Проверяет, завершился ли процесс команды, и очищает ресурсы
static void check_command_termination(void) {
    sig_atomic_t current_pid = pid; // Атомарное чтение
    if (current_pid != -1) {
        int status;
        pid_t result = waitpid(current_pid, &status, WNOHANG);
        if (result == current_pid) {
            log_info("server_shell terminated", "pid=%d", current_pid);
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
    if (!args || !argv) return EINVAL;
    args->iface = NULL;

    const char *argv0 = argv[0];

    while (argc > 1) {
        NEXT_ARG();
        if (matches(*argv, "-h") || matches(*argv, "--help")) {
            usage(argv0);
            return 1;
        }
        args->iface = *argv;
        return 0;
    }
    usage(argv0);
    return 1;
}

static int server_ctx_init(server_ctx_t *ctx, const server_args_t *args) {
    if (!ctx || !args || !args->iface) return -1;
    ctx->sockfd = -1;

    if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, args->iface, 0) != 0) {
        return -1;
    }

    u8 *mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data;
    log_info("server_ctx", "event=iface_ready mac=" MACSTR, MAC2STR((mac)));

    ctx->peer_addr = ctx->bind_addr;
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
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
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

        check_command_termination();

        int had_activity = 0;

        if (ready > 0) {
            if (FD_ISSET(ctx->sockfd, &fds)) {
                if (server_handle_socket_event(ctx, &rx_packet) >= 0) {
                    had_activity = 1;
                }
            }

            if (sh_fd != -1 && FD_ISSET(sh_fd, &fds)) {
                server_handle_shell_event(ctx, &tx_packet);
                had_activity = 1;
            }
        }

        if (had_activity) {
            idle_ticks = 0;
            continue;
        }

        idle_ticks++;
        if (idle_ticks > SERVER_IDLE_TICKS) {
            log_info("server_loop", "event=idle_timeout ticks=%d limit=%d",
                     idle_ticks, SERVER_IDLE_TICKS);
            terminate_shell_process();
            break;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    server_args_t args;
    server_ctx_t ctx;
    packet_dedup_init(&server_rx_dedup);

    int parse_rc = parse_server_args(argc, argv, &args);
    if (parse_rc != 0) {
        return (parse_rc > 0) ? 0 : 1;
    }
    if (server_ctx_init(&ctx, &args) != 0) {
        return 1;
    }

    int rc = server_loop(&ctx);
    server_ctx_deinit(&ctx);
    return (rc == 0) ? 0 : 1;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <interface> [--help]\n", prog);
}
