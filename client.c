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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#define CLIENT_SIGNATURE 0xAABBCCDD // Сигнатура для пакетов от клиента
#define SERVER_SIGNATURE 0xDDCCBBAA // Сигнатура для пакетов от сервера
#define SIGNATURE_LEN 4 // Длина сигнатуры
#define MAX_PAYLOAD_SIZE 1024 // Максимальный размер полезных данных
#define ETHER_TYPE_CUSTOM 0x88B5 // Тип для пользовательских данных

// Стандартный широковещательный MAC-адрес для L2
static const unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static unsigned char             dst_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Структура для заголовка Ethernet и сигнатуры (без полезной нагрузки)
typedef struct my_packet_header {
    struct ether_header eth_hdr; // Заголовок Ethernet
    uint32_t signature;          // Сигнатура (4 байта числом)
    uint32_t payload_size;       // Размер полезной нагрузки
    uint32_t crc;
} __attribute__((packed)) packh_t;

// Структура для полного пакета (заголовок + полезная нагрузка)
typedef struct my_packet {
    packh_t header;                // Заголовок пакета (Ethernet + сигнатура)
    unsigned char payload[MAX_PAYLOAD_SIZE]; // Полезные данные
} __attribute__((packed)) pack_t;

// Включаем неканонический режим терминала (чтобы не ждать ввода Enter)
void set_noncanonical_mode() {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag &= ~(ICANON | ECHO); // Отключаем канонический режим и эхо
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

// Возвращаем нормальный режим
void reset_terminal_mode() {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    tty.c_lflag |= ICANON | ECHO; // Включаем канонический режим и эхо
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}


#define BLOCK_SIZE 4

static const uint8_t key_magic[] = {4, 1, 2, 3};

void enc_dec(const uint8_t *input, uint8_t *output, const uint8_t *key, size_t len) {
    if (len == 0) return; // Обработка случая, когда len = 0

    uint8_t temp[BLOCK_SIZE]; // Временный буфер для хранения промежуточного значения

    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        for (size_t j = 0; j < BLOCK_SIZE && (i + j) < len; j++) {
            temp[j] = input[i + j] ^ key[j] ^ key_magic[j]; // Промежуточное значение
        }
        for (size_t j = 0; j < BLOCK_SIZE && (i + j) < len; j++) {
            output[i + j] = temp[j]; // Запись результата обратно в output
        }
    }
}
// Функция для вычисления контрольной суммы (простая для примера)
uint32_t calculate_checksum(const unsigned char *data, size_t len) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < len; i++) {
        checksum += data[i];
    }
    return checksum;
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

    uint32_t payload_size = ntohl(header->payload_size);

    //расшифровка
    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    //Проверяем crc
    uint32_t crc = header->crc;
    header->crc = 0;
    uint32_t crc_calc = calculate_checksum((const unsigned char *)packet, ret);
    if(crc != crc_calc){
        fprintf(stderr, "error: crc mismatch: recv: %u expected: %u\n", crc, crc_calc);
    }

    // Получаем полезную нагрузку
    ssize_t recv_size = ret - sizeof(packh_t);
    if(recv_size < 0){
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
    ssize_t ret = read(STDIN_FILENO, packet->payload, MAX_PAYLOAD_SIZE);
    if (ret <= 0) return;

    //пишем размер payload
    packet->header.payload_size = htonl(ret);

    // Рассчитываем полный размер пакета с полезной нагрузкой
    size_t packet_len = sizeof(packh_t) + ret;
    packet->header.signature = htonl(CLIENT_SIGNATURE); // Сигнатура клиента
    memcpy(packet->header.eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя

    // Если сервер найден, отправляем данные на MAC-адрес сервера, иначе продолжаем широковещательную отправку
    if (server_found) {
        memcpy(packet->header.eth_hdr.ether_dhost, server_mac, ETH_ALEN); // Отправка на сервер
        memcpy(saddr->sll_addr, server_mac, ETH_ALEN); // Обновляем MAC-адрес сервера в структуре sockaddr_ll
    } else {
        memcpy(packet->header.eth_hdr.ether_dhost, broadcast_mac, ETH_ALEN); // Широковещательная отправка
        memcpy(saddr->sll_addr, broadcast_mac, ETH_ALEN); // Обновляем для широковещательной отправки
    }



    //crc
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
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <dst mac>\n", argv[0]);
        return 1;
    }

    char *interface = argv[1]; // Название интерфейса из аргумента командной строки
    // Конвертация строки в MAC-адрес
    if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &dst_mac[0], &dst_mac[1], &dst_mac[2],
               &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
        fprintf(stderr, "error: invalid mac format passed: %s expected: 11:22:33:44:55:66\n", argv[2]);
        return 1;
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

    reset_terminal_mode();

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
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));


    // Заполнение заголовка Ethernet для первого широковещательного пакета
    memcpy(packet.header.eth_hdr.ether_dhost, broadcast_mac, ETH_ALEN); // Используем стандартный широковещательный MAC-адрес
    memcpy(packet.header.eth_hdr.ether_shost, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя с интерфейса
    packet.header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM); // Тип протокола
    packet.header.signature = htonl(CLIENT_SIGNATURE); // Сигнатура клиента
    packet.header.payload_size = 0;

    printf("Sending initial packet to: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);

    // Заполнение sockaddr_ll структуры для отправки
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = ETH_ALEN;
    memcpy(saddr.sll_addr, broadcast_mac, ETH_ALEN); // Широковещательная отправка

    // Отправляем начальный пакет на сервер для инициирования соединения
    size_t packet_len = sizeof(packet.header);
    //crc
    packet.header.crc = 0;
    uint32_t crc = calculate_checksum((const unsigned char *)&packet, packet_len);
    packet.header.crc = crc;
    //шифруем
    enc_dec(packet.payload, packet.payload, (uint8_t *)&packet.header.crc, packet.header.payload_size);

    if (sendto(sockfd, &packet, packet_len, 0, (struct sockaddr *)&saddr, saddr_len) < 0) {
        perror("Send error");
        close(sockfd);
        return 1;
    }


    // Включаем неканонический режим для захвата каждого символа
    set_noncanonical_mode();

    // Основной цикл отправки каждого нажатия клавиши и приема данных от сервера
    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds); // Ввод с клавиатуры
        FD_SET(sockfd, &fds);       // Прием данных от сервера
        int max_fd = (sockfd > STDIN_FILENO) ? sockfd : STDIN_FILENO;

        int ready = select(max_fd + 1, &fds, NULL, NULL, NULL);
        if (ready < 0) continue;


        if (FD_ISSET(STDIN_FILENO, &fds)) {
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
