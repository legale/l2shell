// server.c - L2 shell server implementation

#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h> //EINTR MACRO
#include <fcntl.h> // Для функции fcntl
#include <net/if.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h> //difftime
#include <unistd.h>

#include "cli_helper.h"
#include "common.h"

#define TIMEOUT 10
#define SERVER_IDLE_TICKS 10

int sh_fd = -1;
volatile sig_atomic_t pid = -1;
static packet_dedup_t server_rx_dedup;

static void start_command_process(const char *command);
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
static ssize_t handle_client_read(server_ctx_t *ctx, pack_t *packet) {
    if (!ctx || ctx->sockfd < 0 || !packet) return -1;

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    struct sockaddr_ll saddr_tmp = {0};
    ssize_t ret = recvfrom(ctx->sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)&saddr_tmp, &saddr_len);
    debug_dump_frame("debug: server rx frame", (const u8 *)packet, (size_t)ret);
    if (ret <= 0) {
        return ret;
    }

    packh_t *header = (packh_t *)packet;
    int payload_size = -1;

    // Добавляем проверку MAC-адреса получателя
    if (memcmp(header->eth_hdr.ether_dhost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) != 0) {
        return -1;
    }

    // Проверяем, что это не наш собственный пакет
    if (memcmp(header->eth_hdr.ether_shost, ctx->ifr.ifr_hwaddr.sa_data, ETH_ALEN) == 0) {
        return -1;
    }
    fprintf(stderr, "%s %s:%d %zd\n", __func__, __FILE__, __LINE__, ret);

    u32 payload_size_host = ntohl(header->payload_size);
    u32 signature_host = ntohl(header->signature);

    if (packet_dedup_should_drop(&server_rx_dedup,
                                 (const u8 *)header->eth_hdr.ether_shost,
                                 ntohl(header->crc),
                                 payload_size_host,
                                 signature_host,
                                 PACKET_DEDUP_WINDOW_NS)) {
        return -1;
    }

    // Копируем saddr, поскольку это правильный отправитель
    memcpy(&ctx->peer_addr, &saddr_tmp, saddr_len);

    payload_size = parse_packet(packet, ret, CLIENT_SIGNATURE);
    if (payload_size < 0) {
        return payload_size;
    }

    // проверяем, запущен ли удаленный шелл
    if (sh_fd == -1) {
        // если нет, запускаем его с командой из полезной нагрузки
        const u8 *cmd_payload = packet->payload;
        size_t cmd_size = (size_t)payload_size;
        // если пейлод пустой или содержит только '\n' — используем дефолтную команду "sh"
        if (cmd_size == 0 || (cmd_size == 1 && packet->payload[0] == '\n')) {
            static const u8 default_cmd[] = "sh";
            cmd_payload = default_cmd;
            cmd_size = sizeof(default_cmd) - 1;
        }
        if (launch_remote_command(cmd_payload, cmd_size) != 0) {
            fprintf(stderr, "error: failed to launch remote command\n");
        }
        return payload_size;
    }
    // отправляем полезную нагрузку в шел, если он уже работает
    (void)write_all(sh_fd, packet->payload, (size_t)payload_size);
    return payload_size;
}

static int launch_remote_command(const u8 *payload, size_t payload_size) {
    if (payload_size == 0) {
        fprintf(stderr, "error: empty remote command payload\n");
        return -1;
    }
    if (payload_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: remote command too long (%zu bytes)\n", payload_size);
        return -1;
    }
    char command[MAX_PAYLOAD_SIZE + 1];
    memcpy(command, payload, payload_size);
    command[payload_size] = '\0';
    if (command[0] == '\0') {
        fprintf(stderr, "error: remote command payload null\n");
        return -1;
    }
    start_command_process(command);
    return 0;
}

// Функция для обработки чтения и записи данных в клиент
static void handle_client_write(server_ctx_t *ctx, pack_t *packet) {
    if (!ctx || ctx->sockfd < 0 || sh_fd < 0 || !packet) return;

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    ssize_t ret = read(sh_fd, packet->payload, MAX_PAYLOAD_SIZE);

    // Проверка успешности чтения из sh_fd
    if (ret <= 0) return; // Если чтение не удалось, выходим

    int packet_len = build_packet(packet, (size_t)ret, (u8 *)ctx->ifr.ifr_hwaddr.sa_data,
                                  (u8 *)ctx->peer_addr.sll_addr, SERVER_SIGNATURE);
    if (packet_len < 0) {
        return;
    }

    // Отладочная информация перед отправкой
    fprintf(stderr, ""
                    "ether_type=0x%04x"
                    " payload_size=%zu"
                    " src=" MACSTR " dst=" MACSTR " sign=0x%04x\n",
            ntohs(packet->header.eth_hdr.ether_type),
            (size_t)ret,
            MAC2STR(packet->header.eth_hdr.ether_shost),
            MAC2STR(packet->header.eth_hdr.ether_dhost),
            ntohl(packet->header.signature));

    ssize_t send_ret = sendto(ctx->sockfd, packet, (size_t)packet_len, 0, (struct sockaddr *)&ctx->peer_addr, saddr_len);

    // Проверка успешности отправки
    if (send_ret < 0) {
        perror("send");
    } else {
        fprintf(stderr, "sent=%zd psize=%zu checksum=%u\n", send_ret, (size_t)ret, ntohl(packet->header.crc));
    }
}

static void start_command_process(const char *command) {
    pid = forkpty(&sh_fd, NULL, NULL, NULL);
    if (pid == 0) {
        execlp(command, command, NULL);
        perror("execlp failed");
        exit(1);
    }
    if (pid < 0) {
        perror("forkpty failed");
        exit(1);
    }
    fprintf(stderr, "started proc with pid: %d\n", pid);
}

// Проверяет, завершился ли процесс команды, и очищает ресурсы
static void check_command_termination(void) {
    sig_atomic_t current_pid = pid; // Атомарное чтение
    if (current_pid != -1) {
        int status;
        pid_t result = waitpid(current_pid, &status, WNOHANG);
        if (result == current_pid) {
            fprintf(stderr, "proc with pid %d terminated\n", current_pid);
            close(sh_fd);
            sh_fd = -1;
            pid = -1;
            return;
        }
    }
}

static int parse_server_args(int argc, char **argv, server_args_t *args) {
    if (!args || !argv) return EINVAL;
    memset(args, 0, sizeof(*args));

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

static int init_server_context(server_ctx_t *ctx, const server_args_t *args) {
    if (!ctx || !args || !args->iface) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->sockfd = -1;

    if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, args->iface, 0) != 0) {
        return -1;
    }

    u8 *mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data;
    fprintf(stderr, "interface mac=" MACSTR "\n", MAC2STR((mac)));

    ctx->peer_addr = ctx->bind_addr;
    return 0;
}

static void server_deinit(server_ctx_t *ctx) {
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
            if (sh_fd > max_fd) max_fd = sh_fd;
        }

        int ready = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("select");
            return -1;
        }

        check_command_termination();
        if (ready == 0) {
            if (++idle_ticks > SERVER_IDLE_TICKS) {
                break;
            }
            continue;
        }
        idle_ticks = 0;

        if (FD_ISSET(ctx->sockfd, &fds)) {
            (void)handle_client_read(ctx, &rx_packet);
        }
        if (sh_fd != -1 && FD_ISSET(sh_fd, &fds)) {
            handle_client_write(ctx, &tx_packet);
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
    if (init_server_context(&ctx, &args) != 0) {
        return 1;
    }

    int rc = server_loop(&ctx);
    server_deinit(&ctx);
    return (rc == 0) ? 0 : 1;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <interface> [--help]\n", prog);
}
