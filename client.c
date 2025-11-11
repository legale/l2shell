#ifndef __USE_MISC
#define __USE_MISC 1
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <arpa/inet.h>
#include <fcntl.h> // Для функции fcntl
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

#include "common.h"

#define COMMAND_RESPONSE_TIMEOUT_NS (1500ULL * NSEC_PER_MSEC)

static unsigned char dst_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static struct termios original_tty;
static int tty_saved = 0;
static int term_fd = -1;
static int input_fd = -1;
static packet_dedup_t client_rx_dedup;

void reset_terminal_mode();
static int stdin_in_foreground(void);

static int acquire_terminal_fd(void) {
    if (term_fd >= 0) {
        return term_fd;
    }

    if (isatty(STDIN_FILENO)) {
        term_fd = STDIN_FILENO;
        input_fd = STDIN_FILENO;
        return term_fd;
    }

    term_fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (term_fd >= 0) {
        input_fd = term_fd;
        return term_fd;
    }

    perror("open /dev/tty");

    return -1;
}

// Включаем неканонический режим, по желанию отключаем локальное эхо
void set_noncanonical_mode(int enable_local_echo) {
    int fd = acquire_terminal_fd();
    if (fd < 0) {
        fprintf(stderr, "warning: interactive tty not found, can't disable local echo\n");
        return;
    }

    if (!tty_saved) {
        if (tcgetattr(fd, &original_tty) == -1) {
            perror("tcgetattr");
            return;
        }
        tty_saved = 1;
    }

    struct termios raw = original_tty;
    cfmakeraw(&raw);
    raw.c_lflag |= ISIG;
    if (enable_local_echo) {
        raw.c_lflag |= (ECHO | ECHONL | ECHOE | ECHOK);
    } else {
        raw.c_lflag &= ~(ECHO | ECHONL | ECHOE | ECHOK | ECHOCTL | ECHOKE);
    }
    if (tcsetattr(fd, TCSAFLUSH, &raw) == -1) {
        perror("tcsetattr");
    }
}

static int stdin_in_foreground(void) {
    if (!isatty(STDIN_FILENO)) {
        return 0;
    }
    pid_t fg = tcgetpgrp(STDIN_FILENO);
    if (fg == -1) {
        return 0;
    }
    return fg == getpgrp();
}

// Возвращаем исходный режим терминала
void reset_terminal_mode() {
    if (!tty_saved) {
        return;
    }

    int fd = acquire_terminal_fd();
    if (fd < 0) {
        return;
    }

    if (tcsetattr(fd, TCSANOW, &original_tty) == -1) {
        perror("tcsetattr");
    }

    if (term_fd >= 0 && term_fd != STDIN_FILENO) {
        close(term_fd);
    }
    term_fd = -1;
    input_fd = -1;
}

static void handle_exit_signal(int signo) {
    reset_terminal_mode();
    signal(signo, SIG_DFL);
    raise(signo);
}

static void install_signal_handlers() {
    struct sigaction sa = {0};
    sa.sa_handler = handle_exit_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
}

// Функция для обработки чтения данных с сервера
int handle_server_read(int sockfd, pack_t *packet, struct sockaddr_ll *saddr, unsigned char *server_mac, int *server_mac_known) {
    socklen_t saddr_len = sizeof(*saddr);
    memset(packet, 0, sizeof(pack_t));
    ssize_t ret = recvfrom(sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)saddr, &saddr_len);

    if (ret <= 0) return 0;

    packh_t *header = (packh_t *)packet;

    // Проверяем тип протокола и сигнатуру пакета
    if (ntohs(header->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM) return 0;
    // printf("recv: %zd %04x\n", ret, ntohl(header->signature));

    if (ntohl(header->signature) != SERVER_SIGNATURE) return 0;

    uint32_t payload_size = ntohl(header->payload_size);

    if (packet_dedup_should_drop(&client_rx_dedup,
                                 (const uint8_t *)header->eth_hdr.ether_shost,
                                 ntohl(header->crc),
                                 payload_size,
                                 ntohl(header->signature),
                                 PACKET_DEDUP_WINDOW_NS)) {
        return 0;
    }

    // Запоминаем MAC-адрес сервера при первом получении
    if (!(*server_mac_known) || memcmp(server_mac, header->eth_hdr.ether_shost, ETH_ALEN) != 0) {
        memcpy(server_mac, header->eth_hdr.ether_shost, ETH_ALEN);
        *server_mac_known = 1;
        printf("server mac saved: ");
        for (int i = 0; i < ETH_ALEN - 1; i++) {
            printf("%02x:", server_mac[i]);
        }
        printf("%02x\n", server_mac[ETH_ALEN - 1]);
    }

    // расшифровка
    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    // Проверяем crc
    uint32_t crc_net = header->crc;
    header->crc = 0;
    uint32_t crc_calc = calculate_checksum((const unsigned char *)packet, ret);
    header->crc = crc_net;
    uint32_t crc_host = ntohl(crc_net);
    if (crc_host != crc_calc) {
        fprintf(stderr, "error: crc mismatch: recv: %u expected: %u\n", crc_host, crc_calc);
        return 0;
    }

    // Получаем полезную нагрузку
    ssize_t recv_size = ret - sizeof(packh_t);
    if (recv_size < 0) {
        fprintf(stderr, "error: recv_size: %zd\n", recv_size);
        return 0;
    }

    if (payload_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: payload size too large: %u\n", payload_size);
        return 0;
    }

    // Выводим полезную нагрузку на экран
    // printf("payload: %zd\n", payload_size);
    write(STDOUT_FILENO, packet->payload, payload_size);
    return 1;
}

// Функция для обработки записи данных на сервер
void handle_server_write(int sockfd, pack_t *packet, struct ifreq *ifr, struct sockaddr_ll *saddr, const unsigned char *server_mac, int server_mac_known) {
    // fprintf(stderr, "%s %s:%d\n", __func__, __FILE__, __LINE__);
    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    int fd = (input_fd >= 0) ? input_fd : STDIN_FILENO;
    ssize_t ret = read(fd, packet->payload, MAX_PAYLOAD_SIZE);
    if (ret <= 0) return;

    if (!server_mac_known) {
        fprintf(stderr, "error: server MAC address unknown, cannot send payload\n");
        return;
    }

    // пишем размер payload
    packet->header.payload_size = htonl(ret);

    // Рассчитываем полный размер пакета с полезной нагрузкой
    size_t packet_len = sizeof(packh_t) + ret;
    packet->header.signature = htonl(CLIENT_SIGNATURE);                            // Сигнатура клиента
    memcpy(packet->header.eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя

    memcpy(packet->header.eth_hdr.ether_dhost, server_mac, ETH_ALEN);
    memcpy(saddr->sll_addr, server_mac, ETH_ALEN);

    // crc
    packet->header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)packet, packet_len);
    packet->header.crc = htonl(crc);

    uint32_t payload_size = ntohl(packet->header.payload_size);

    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)saddr, saddr_len) < 0) {
        perror("Send error");
    }
}

static int send_text_command(int sockfd, pack_t *packet, struct ifreq *ifr,
                             struct sockaddr_ll *saddr, const unsigned char *server_mac,
                             int server_mac_known, const char *text) {
    if (!server_mac_known || !text) {
        fprintf(stderr, "error: cannot send command without known server mac\n");
        return -1;
    }

    size_t cmd_len = strlen(text);
    int needs_enter = (cmd_len == 0 ||
                       (text[cmd_len - 1] != '\r' && text[cmd_len - 1] != '\n'));
    size_t payload_len = cmd_len + (needs_enter ? 1 : 0);

    if (payload_len > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: command too long (%zu bytes)\n", payload_len);
        return -1;
    }

    memcpy(packet->payload, text, cmd_len);
    if (needs_enter) {
        packet->payload[cmd_len] = '\r';
    }

    packet->header.payload_size = htonl((uint32_t)payload_len);
    packet->header.signature = htonl(CLIENT_SIGNATURE);
    memcpy(packet->header.eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(packet->header.eth_hdr.ether_dhost, server_mac, ETH_ALEN);
    memcpy(saddr->sll_addr, server_mac, ETH_ALEN);

    size_t packet_len = sizeof(packh_t) + payload_len;
    packet->header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)packet, packet_len);
    packet->header.crc = htonl(crc);

    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_len);

    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)saddr, sizeof(*saddr)) < 0) {
        perror("Send error");
        return -1;
    }

    return 0;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <interface> <dst mac> [command] [--local-echo]\n"
                "       %s --tty-loop [--local-echo]\n",
                argv[0], argv[0]);
        return 1;
    }

    char *interface = NULL;
    char *dst_mac_str = NULL;
    char *single_command = NULL;
    int local_echo_requested = 0;
    int tty_loop_mode = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--local-echo") == 0) {
            local_echo_requested = 1;
            continue;
        }
        if (strcmp(argv[i], "--tty-loop") == 0) {
            tty_loop_mode = 1;
            continue;
        }
        if (!interface) {
            interface = argv[i];
            continue;
        }
        if (!dst_mac_str) {
            dst_mac_str = argv[i];
            continue;
        }
        if (!single_command) {
            single_command = argv[i];
            continue;
        }
        fprintf(stderr, "error: unexpected argument: %s\n", argv[i]);
        return 1;
    }

    if (tty_loop_mode && (interface || dst_mac_str || single_command)) {
        fprintf(stderr, "error: --tty-loop can't run with interface/MAC/command parameters\n");
        return 1;
    }

    int send_command_mode = (single_command != NULL);
    if (!tty_loop_mode) {
        if (!interface || !dst_mac_str) {
            fprintf(stderr, "error: interface and server MAC required\n");
            return 1;
        }

        if (sscanf(dst_mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &dst_mac[0], &dst_mac[1], &dst_mac[2],
                   &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
            fprintf(stderr, "error: invalid mac format passed: %s expected: 11:22:33:44:55:66\n", dst_mac_str);
            return 1;
        }
    }

    atexit(reset_terminal_mode);
    install_signal_handlers();
    packet_dedup_init(&client_rx_dedup);

    if (tty_loop_mode) {
        set_noncanonical_mode(local_echo_requested);
        unsigned char buf[256];
        while (1) {
            int fd = (input_fd >= 0) ? input_fd : acquire_terminal_fd();
            if (fd < 0) break;
            ssize_t rd = read(fd, buf, sizeof(buf));
            if (rd <= 0) {
                break;
            }
            if (write(STDOUT_FILENO, buf, rd) < 0) {
                break;
            }
        }
        reset_terminal_mode();
        return 0;
    }

    int sockfd;
    struct ifreq ifr = {0};
    struct sockaddr_ll saddr = {0};
    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    pack_t packet = {0};
    pack_t packet2 = {0};
    fd_set fds;
    unsigned char server_mac[ETH_ALEN] = {0}; // MAC-адрес сервера
    int server_mac_known = 0;                 // Флаг, известен ли MAC сервера
    int command_sent = 0;
    int response_seen = 0;
    int exit_code = 0;
    uint64_t command_deadline_ns = 0;

    if (!tty_loop_mode) {
        memcpy(server_mac, dst_mac, ETH_ALEN);
        server_mac_known = 1;
    }

    // Создание RAW сокета
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    // Получение индекса интерфейса с помощью if_nametoindex
    int ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        perror("Interface index error");
        close(sockfd);
        return 1;
    }

    // Получение MAC-адреса отправителя для указанного интерфейса с использованием ioctl
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Getting MAC address error");
        close(sockfd);
        return 1;
    }

    // Установка сокета в неблокирующий режим
    // int flags = fcntl(sockfd, F_GETFL, 0);
    // fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 150000; // 150 мс
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    // Заполнение заголовка Ethernet для первого пакета
    const unsigned char *initial_dst = server_mac_known ? server_mac : broadcast_mac;
    memcpy(packet.header.eth_hdr.ether_dhost, initial_dst, ETH_ALEN);
    memcpy(packet.header.eth_hdr.ether_shost, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя с интерфейса
    packet.header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);                 // Тип протокола
    packet.header.signature = htonl(CLIENT_SIGNATURE);                           // Сигнатура клиента
    packet.header.payload_size = 0;

    if (!send_command_mode) {
        printf("Sending initial packet to: %02x:%02x:%02x:%02x:%02x:%02x\n",
               dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    }

    // Заполнение sockaddr_ll структуры для отправки
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = ETH_ALEN;
    memcpy(saddr.sll_addr, initial_dst, ETH_ALEN);

    // Отправляем начальный пакет на сервер для инициирования соединения
    size_t packet_len = sizeof(packet.header);
    // crc
    packet.header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)&packet, packet_len);
    packet.header.crc = htonl(crc);
    // шифруем
    enc_dec(packet.payload, packet.payload, (uint8_t *)&packet.header.crc, packet.header.payload_size);

    if (sendto(sockfd, &packet, packet_len, 0, (struct sockaddr *)&saddr, saddr_len) < 0) {
        perror("Send error");
        close(sockfd);
        return 1;
    }

    int interactive_input_enabled = !send_command_mode;
    if (interactive_input_enabled) {
        if (isatty(STDIN_FILENO)) {
            if (stdin_in_foreground()) {
                set_noncanonical_mode(local_echo_requested);
            } else {
                interactive_input_enabled = 0;
                fprintf(stderr, "warning: stdin is background TTY; interactive input disabled\n");
            }
        }
    }

    if (send_command_mode) {
        if (send_text_command(sockfd, &packet, &ifr, &saddr, server_mac, server_mac_known, single_command) == 0) {
            command_sent = 1;
        } else {
            fprintf(stderr, "error: failed to send command payload\n");
            exit_code = 1;
        }

        if (!command_sent) {
            reset_terminal_mode();
            close(sockfd);
            return exit_code;
        }

        command_deadline_ns = monotonic_ns() + COMMAND_RESPONSE_TIMEOUT_NS;
    }

    // Основной цикл отправки и приема данных от сервера
    while (1) {
        FD_ZERO(&fds);
        int max_fd = sockfd;
        if (interactive_input_enabled) {
            int input_ready_fd = (input_fd >= 0) ? input_fd : STDIN_FILENO;
            FD_SET(input_ready_fd, &fds);
            if (input_ready_fd > max_fd) {
                max_fd = input_ready_fd;
            }
        }
        FD_SET(sockfd, &fds);

        struct timeval select_tv;
        struct timeval *select_timeout = NULL;
        if (send_command_mode) {
            uint64_t now_ns = monotonic_ns();
            if (now_ns >= command_deadline_ns) {
                break;
            }
            uint64_t remaining_ns = command_deadline_ns - now_ns;
            select_tv.tv_sec = (time_t)(remaining_ns / 1000000000ULL);
            select_tv.tv_usec = (suseconds_t)((remaining_ns % 1000000000ULL) / 1000ULL);
            select_timeout = &select_tv;
        }

        int ready = select(max_fd + 1, &fds, NULL, NULL, select_timeout);
        if (ready < 0) {
            continue;
        }

        if (ready == 0) {
            if (send_command_mode) {
                break;
            }
            continue;
        }

        if (interactive_input_enabled) {
            int input_ready_fd = (input_fd >= 0) ? input_fd : STDIN_FILENO;
            if (FD_ISSET(input_ready_fd, &fds)) {
                handle_server_write(sockfd, &packet, &ifr, &saddr, server_mac, server_mac_known);
            }
        }

        if (FD_ISSET(sockfd, &fds)) {
            int got_data = handle_server_read(sockfd, &packet2, &saddr, server_mac, &server_mac_known);
            if (send_command_mode && got_data) {
                response_seen = 1;
                command_deadline_ns = monotonic_ns() + COMMAND_RESPONSE_TIMEOUT_NS;
            }
        }
    }

    if (send_command_mode && !response_seen) {
        unsigned long long timeout_ms = COMMAND_RESPONSE_TIMEOUT_NS / NSEC_PER_MSEC;
        fprintf(stderr, "error: no response received within %llums window\n", timeout_ms);
        exit_code = exit_code ? exit_code : 1;
    }

    reset_terminal_mode();
    close(sockfd);
    return exit_code;
}
