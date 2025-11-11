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
#include <unistd.h>

#include "common.h"

static unsigned char dst_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static struct termios original_tty;
static int tty_saved = 0;
static int term_fd = -1;
static int input_fd = -1;
static packet_dedup_t client_rx_dedup;

void reset_terminal_mode();

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
        fprintf(stderr, "warning: интерактивный tty не найден, локальное эхо отключить нельзя\n");
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
void handle_server_read(int sockfd, pack_t *packet, struct sockaddr_ll *saddr, unsigned char *server_mac, int *server_found) {
    socklen_t saddr_len = 0;
    memset(packet, 0, sizeof(pack_t));
    ssize_t ret = recvfrom(sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)saddr, &saddr_len);

    if (ret <= 0) return;

    packh_t *header = (packh_t *)packet;

    // Проверяем тип протокола и сигнатуру пакета
    if (ntohs(header->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM) return;
    // printf("recv: %zd %04x\n", ret, ntohl(header->signature));

    if (ntohl(header->signature) != SERVER_SIGNATURE) return;

    uint32_t payload_size = ntohl(header->payload_size);

    if (packet_dedup_should_drop(&client_rx_dedup,
                                 (const uint8_t *)header->eth_hdr.ether_shost,
                                 header->crc,
                                 payload_size,
                                 ntohl(header->signature),
                                 PACKET_DEDUP_WINDOW_NS)) {
        return;
    }

    // Запоминаем MAC-адрес сервера при первом получении
    if (!(*server_found)) {
        memcpy(server_mac, header->eth_hdr.ether_shost, ETH_ALEN);
        *server_found = 1;
        printf("server mac saved: ");
        for (int i = 0; i < ETH_ALEN - 1; i++) {
            printf("%02x:", server_mac[i]);
        }
        printf("%02x\n", server_mac[ETH_ALEN - 1]);
    }

    // расшифровка
    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    // Проверяем crc
    uint32_t crc = header->crc;
    header->crc = 0;
    uint32_t crc_calc = calculate_checksum((const unsigned char *)packet, ret);
    if (crc != crc_calc) {
        fprintf(stderr, "error: crc mismatch: recv: %u expected: %u\n", crc, crc_calc);
    }

    // Получаем полезную нагрузку
    ssize_t recv_size = ret - sizeof(packh_t);
    if (recv_size < 0) {
        fprintf(stderr, "error: recv_size: %zd\n", recv_size);
        return;
    }

    if (payload_size > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "error: payload size too large: %u\n", payload_size);
        return;
    }

    // Выводим полезную нагрузку на экран
    // printf("payload: %zd\n", payload_size);
    write(STDOUT_FILENO, packet->payload, payload_size);
}

// Функция для обработки записи данных на сервер
void handle_server_write(int sockfd, pack_t *packet, struct ifreq *ifr, struct sockaddr_ll *saddr, unsigned char *server_mac, int server_found) {
    // fprintf(stderr, "%s %s:%d\n", __func__, __FILE__, __LINE__);
    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    int fd = (input_fd >= 0) ? input_fd : STDIN_FILENO;
    ssize_t ret = read(fd, packet->payload, MAX_PAYLOAD_SIZE);
    if (ret <= 0) return;

    // пишем размер payload
    packet->header.payload_size = htonl(ret);

    // Рассчитываем полный размер пакета с полезной нагрузкой
    size_t packet_len = sizeof(packh_t) + ret;
    packet->header.signature = htonl(CLIENT_SIGNATURE);                            // Сигнатура клиента
    memcpy(packet->header.eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя

    // Если сервер найден, отправляем данные на MAC-адрес сервера, иначе продолжаем широковещательную отправку
    if (server_found) {
        memcpy(packet->header.eth_hdr.ether_dhost, server_mac, ETH_ALEN); // Отправка на сервер
        memcpy(saddr->sll_addr, server_mac, ETH_ALEN);                    // Обновляем MAC-адрес сервера в структуре sockaddr_ll
    } else {
        memcpy(packet->header.eth_hdr.ether_dhost, broadcast_mac, ETH_ALEN); // Широковещательная отправка
        memcpy(saddr->sll_addr, broadcast_mac, ETH_ALEN);                    // Обновляем для широковещательной отправки
    }

    // crc
    packet->header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)packet, packet_len);
    packet->header.crc = crc;

    uint32_t payload_size = ntohl(packet->header.payload_size);

    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)saddr, saddr_len) < 0) {
        perror("Send error");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> <dst mac> [--local-echo]\n"
                        "       %s --tty-loop [--local-echo]\n",
                argv[0], argv[0]);
        return 1;
    }

    char *interface = NULL;
    char *dst_mac_str = NULL;
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
        fprintf(stderr, "error: unexpected argument: %s\n", argv[i]);
        return 1;
    }

    if (tty_loop_mode && (interface || dst_mac_str)) {
        fprintf(stderr, "error: --tty-loop нельзя комбинировать с параметрами интерфейса/MAC\n");
        return 1;
    }

    if (!tty_loop_mode) {
        if (!interface || !dst_mac_str) {
            fprintf(stderr, "error: требуется интерфейс и MAC сервера\n");
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
    unsigned char server_mac[ETH_ALEN]; // MAC-адрес сервера
    int server_found = 0;               // Флаг, найден ли сервер

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

    // Заполнение заголовка Ethernet для первого широковещательного пакета
    memcpy(packet.header.eth_hdr.ether_dhost, broadcast_mac, ETH_ALEN);          // Используем стандартный широковещательный MAC-адрес
    memcpy(packet.header.eth_hdr.ether_shost, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя с интерфейса
    packet.header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);                 // Тип протокола
    packet.header.signature = htonl(CLIENT_SIGNATURE);                           // Сигнатура клиента
    packet.header.payload_size = 0;

    printf("Sending initial packet to: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    // Заполнение sockaddr_ll структуры для отправки
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = ETH_ALEN;
    memcpy(saddr.sll_addr, broadcast_mac, ETH_ALEN); // Широковещательная отправка

    // Отправляем начальный пакет на сервер для инициирования соединения
    size_t packet_len = sizeof(packet.header);
    // crc
    packet.header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)&packet, packet_len);
    packet.header.crc = crc;
    // шифруем
    enc_dec(packet.payload, packet.payload, (uint8_t *)&packet.header.crc, packet.header.payload_size);

    if (sendto(sockfd, &packet, packet_len, 0, (struct sockaddr *)&saddr, saddr_len) < 0) {
        perror("Send error");
        close(sockfd);
        return 1;
    }

    // Включаем неканонический режим для захвата каждого символа
    set_noncanonical_mode(local_echo_requested);

    // Основной цикл отправки каждого нажатия клавиши и приема данных от сервера
    while (1) {
        FD_ZERO(&fds);
        int input_ready_fd = (input_fd >= 0) ? input_fd : STDIN_FILENO;
        FD_SET(input_ready_fd, &fds); // Ввод с клавиатуры
        FD_SET(sockfd, &fds);         // Прием данных от сервера
        int max_fd = (sockfd > input_ready_fd) ? sockfd : input_ready_fd;

        int ready = select(max_fd + 1, &fds, NULL, NULL, NULL);
        if (ready < 0) continue;

        if (FD_ISSET(input_ready_fd, &fds)) {
            handle_server_write(sockfd, &packet, &ifr, &saddr, server_mac, server_found);
        }

        if (FD_ISSET(sockfd, &fds)) {
            handle_server_read(sockfd, &packet2, &saddr, server_mac, &server_found);
        }
    }

    reset_terminal_mode();
    close(sockfd);
    return 0;
}
