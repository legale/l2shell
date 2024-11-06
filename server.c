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
#include <pty.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h> //EINTR MACRO
#include <unistd.h>
#include <time.h> //difftime

#define CLIENT_SIGNATURE 0xAABBCCDD // Сигнатура для пакетов от клиента
#define SERVER_SIGNATURE 0xDDCCBBAA // Сигнатура для пакетов от сервера
#define SIGNATURE_LEN 4 // Длина сигнатуры
#define MAX_PAYLOAD_SIZE 1024 // Максимальный размер полезных данных
#define ETHER_TYPE_CUSTOM 0x88B5 // Тип для пользовательских данных

// Стандартный широковещательный MAC-адрес для L2
static const unsigned char broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff,
                                                      0xff, 0xff, 0xff};

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

int sh_fd = -1;
volatile sig_atomic_t pid = -1;

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

ssize_t write_all(int fd, const void *buf, size_t count) {
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
ssize_t handle_client_read(int sockfd, pack_t *packet, struct sockaddr_ll *saddr, struct ifreq *ifr) {
    

    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    struct sockaddr_ll saddr_tmp = {0};
    ssize_t ret = recvfrom(sockfd, packet, sizeof(pack_t), 0, (struct sockaddr *)&saddr_tmp, &saddr_len);
    
    if (ret <= 0){
      return ret;
    }

    packh_t *header = (packh_t *)packet;
    
    // Проверяем тип и сигнатуру пакета
    if (ntohs(header->eth_hdr.ether_type) != ETHER_TYPE_CUSTOM ||
        ntohl(header->signature) != CLIENT_SIGNATURE) {
        return -1;
    }

    // Добавляем проверку MAC-адреса получателя
    // Пакет должен быть или широковещательным или предназначен нашему интерфейсу
    if (memcmp(header->eth_hdr.ether_dhost, broadcast_mac, ETH_ALEN) != 0 && 
        memcmp(header->eth_hdr.ether_dhost, ifr->ifr_hwaddr.sa_data, ETH_ALEN) != 0) {
        return -1;
    }

    // Проверяем, что это не наш собственный пакет
    if (memcmp(header->eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN) == 0) {
        return -1;
    }
    fprintf(stderr, "%s %s:%d %zd\n", __func__, __FILE__, __LINE__, ret);

    // Копируем saddr, поскольку это правильный отправитель
    memcpy(saddr, &saddr_tmp, saddr_len);

    uint32_t payload_size = ntohl(header->payload_size);
    if (payload_size > MAX_PAYLOAD_SIZE) {
      fprintf(stderr, "error: payload size too large: %u\n", payload_size);
      return -1;
    }

  if (payload_size > 0 && sh_fd != -1) {
      //расшифровка
      enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);


      // чексумма
      uint32_t crc = packet->header.crc;
      packet->header.crc = 0;
      uint32_t crc_calc = calculate_checksum((uint8_t *)packet, ret);
      if(crc != crc_calc){
        fprintf(stderr, "error: crc mismatch: recv: %u expected: %u\n", crc, crc_calc);
      }
      
      // Отправляем данные в команду и выводим информацию
      printf("recv: %zd, psize: %u crc: %u crc_calc: %u\n", ret, payload_size, crc, crc_calc);
      write_all(sh_fd, packet->payload, payload_size);
  }
  return payload_size;
}

// Функция для обработки чтения и записи данных в клиент
void handle_client_write(int sockfd, int sh_fd, pack_t *packet,
                         struct sockaddr_ll *saddr, struct ifreq *ifr) {
    socklen_t saddr_len = sizeof(struct sockaddr_ll);
    ssize_t ret = read(sh_fd, packet->payload, MAX_PAYLOAD_SIZE);
    
    // Проверка успешности чтения из sh_fd
    if (ret <= 0) return; // Если чтение не удалось, выходим

    // Заполнение заголовка eth
    packet->header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
    packet->header.payload_size = htonl(ret);
    memcpy(packet->header.eth_hdr.ether_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN); // MAC-адрес отправителя
    memcpy(packet->header.eth_hdr.ether_dhost, saddr->sll_addr, ETH_ALEN); // MAC-адрес получателя (клиента)
    packet->header.signature = htonl(SERVER_SIGNATURE); // Сигнатура сервера

    uint32_t payload_size = ntohl(packet->header.payload_size);

    // Отладочная информация перед отправкой
    printf("ether_type: 0x%04x ", ntohs(packet->header.eth_hdr.ether_type));
    printf("payload_size: %u ", payload_size);
    printf("src: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x%s", (unsigned char)packet->header.eth_hdr.ether_shost[i], (i < ETH_ALEN - 1) ? ":" : " ");
    }
    printf("dst: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x%s", (unsigned char)packet->header.eth_hdr.ether_dhost[i], (i < ETH_ALEN - 1) ? ":" : " ");
    }
    printf("sign.: 0x%08x\n", ntohl(packet->header.signature));

    //data size
    size_t packet_len = sizeof(packh_t) + ret;


    //crc
    packet->header.crc = 0;
    uint32_t crc = calculate_checksum((const uint8_t *)packet, packet_len);
    packet->header.crc = crc;

    

    //расшифровка
    enc_dec(packet->payload, packet->payload, (uint8_t *)&packet->header.crc, payload_size);

    // Размер отправляемых данных: заголовок + полезная нагрузка
    ssize_t send_ret = sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)saddr, saddr_len);
    
    // Проверка успешности отправки
    if (send_ret < 0) {
        perror("send");
    } else {
        printf("sent: %zd psize: %u checksum: %u\n", send_ret, ntohl(packet->header.payload_size), crc);
    }
}


// Функция для запуска процесса команды
void start_command_process(char *command) {
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
  printf("started proc with pid: %d\n", pid);
}

#define TIMEOUT 10
time_t last_data_time = 0;

// Функция для завершения процесса команды
void check_command_termination() {
    sig_atomic_t current_pid = pid;  // Атомарное чтение
    if (current_pid != -1) {
        int status;
        pid_t result = waitpid(current_pid, &status, WNOHANG);
        if (result == current_pid) {
            printf("proc with pid %d terminated\n", current_pid);
            close(sh_fd);
            sh_fd = -1;
            pid = -1;
        }

        // Проверка таймера
        time_t current_time = time(NULL);
        if (!last_data_time) last_data_time = current_time;
        if (difftime(current_time, last_data_time) >= TIMEOUT) {
            printf("No data received for 10 seconds. Terminating session.\n");
            kill(current_pid, SIGTERM);  // Завершение процесса
            close(sh_fd);
            sh_fd = -1;
            pid = -1;
            last_data_time = 0;
        } else {
            // Сброс таймера
            last_data_time = current_time;
        }
    }
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <interface> <command>\n", argv[0]);
    return 1;
  }

  char *interface = argv[1];
  char *command = argv[2];
  int sockfd;
  struct sockaddr_ll saddr = {0};
  pack_t packet = {0};
  pack_t packet2 = {0};
  struct ifreq ifr = {0};

  sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_CUSTOM));
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  // int flags = fcntl(sockfd, F_GETFL, 0);
  // fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 500000; // 500 мс
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

  int ifindex = if_nametoindex(interface);
  if (ifindex == 0) {
    perror("iface index error");
    return 1;
  }

  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
    perror("iface get mac");
    return 1;
  }

  printf("interface mac: ");
  for (int i = 0; i < ETH_ALEN - 1; i++) {
    printf("%02x:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
  }
  printf("%02x\n", (unsigned char)ifr.ifr_hwaddr.sa_data[ETH_ALEN - 1]);


  // Привязка сокета к интерфейсу
  saddr.sll_family = AF_PACKET;
  saddr.sll_protocol = htons(ETHER_TYPE_CUSTOM);
  saddr.sll_ifindex = ifindex; // Привязка к интерфейсу

  if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
      perror("bind");
      close(sockfd);
      return 1;
  }



  fd_set fds;
  while (1) {
    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    if (sh_fd != -1) {
      FD_SET(sh_fd, &fds);
    }
    int max_fd = (sh_fd > sockfd) ? sh_fd : sockfd;

    select(max_fd + 1, &fds, NULL, NULL, NULL);

    check_command_termination();

    if (FD_ISSET(sockfd, &fds)) {
      ssize_t packet_len = handle_client_read(sockfd, &packet, &saddr, &ifr);
      if (packet_len > 0 && sh_fd == -1) {
        start_command_process(command);
      }
    }

    if (sh_fd != -1 && FD_ISSET(sh_fd, &fds)) {
      handle_client_write(sockfd, sh_fd, &packet2, &saddr, &ifr);
    }
  }

  close(sockfd);
  return 0;
}
