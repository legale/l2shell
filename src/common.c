// common.c - Common functions for packet handling

#include "common.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h> //fchmod
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

const u8 broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
void debug_dump_frame(const char *prefix, const u8 *data, size_t len) {
    if (!data || !len) return;

    const char *path = "logs/clientserver.log";
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);

    if (fd < 0)
        return;
    (void)fchmod(fd, (mode_t)0666);

    FILE *log_file = fdopen(fd, "a");
    if (!log_file) {
        close(fd);
        return;
    }

    fprintf(log_file, "%s len=%zu\n", prefix, len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(log_file, "%04zx:", i);
        size_t line_end = (i + 16 < len) ? i + 16 : len;
        for (size_t j = i; j < line_end; ++j) {
            fprintf(log_file, " %02x", data[j]);
        }
        fputc('\n', log_file);
    }

    fclose(log_file);
}

int log_redirect_stdio(const char *path) {
    int fd;

    if (!path || !path[0])
        return 0;

    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd < 0)
        return -1;

    if (dup2(fd, STDOUT_FILENO) < 0) {
        close(fd);
        return -1;
    }
    if (dup2(fd, STDERR_FILENO) < 0) {
        close(fd);
        return -1;
    }

    if (fd > STDERR_FILENO)
        close(fd);

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    return 0;
}

static void log_internal(const char *level, const char *tag, const char *fmt, va_list ap) {
    if (!level) level = "info";
    if (!tag) tag = "app";
    fprintf(stderr, "level=%s tag=%s ", level, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_info(const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal("info", tag, fmt, ap);
    va_end(ap);
}

void log_error_errno(const char *tag, const char *fmt, ...) {
    int err = errno;
    va_list ap;
    va_start(ap, fmt);
    char buf[256];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    log_error(tag, "errno=%d err='%s' %s", err, strerror(err), buf);
    va_end(ap);
}

void log_error(const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    log_internal("error", tag, fmt, ap);
    va_end(ap);
}

int init_packet_socket(int *sockfd, struct ifreq *ifr, struct sockaddr_ll *bind_addr, const char *iface, int bind_to_device) {
    if (!sockfd || !ifr || !bind_addr) return -1;

    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_CUSTOM));
    if (*sockfd < 0) {
        log_error_errno("packet_socket", "socket");
        return -1;
    }

    int flags = fcntl(*sockfd, F_GETFL, 0);
    if (flags < 0) {
        log_error_errno("packet_socket", "fcntl_get");
        deinit_packet_socket(sockfd);
        return -1;
    }
    if (fcntl(*sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error_errno("packet_socket", "fcntl_set");
        deinit_packet_socket(sockfd);
        return -1;
    }

    struct timeval tv = {.tv_sec = 1, .tv_usec = 500000};
    if (setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0) {
        log_error_errno("packet_socket", "setsockopt_rcvtimeo");
        deinit_packet_socket(sockfd);
        return -1;
    }

    int ifindex = 0;
    if (iface && *iface) {
        if (bind_to_device) {
            if (setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, iface, strnlen(iface, IFNAMSIZ)) < 0) {
                log_error_errno("packet_socket", "bindtodevice");
                deinit_packet_socket(sockfd);
                return -1;
            }
        }

        ifindex = if_nametoindex(iface);
        if (!ifindex) {
            log_error_errno("packet_socket", "if_nametoindex");
            deinit_packet_socket(sockfd);
            return -1;
        }

        memset(ifr, 0, sizeof(*ifr));
        strncpy(ifr->ifr_name, iface, IFNAMSIZ - 1);
        ifr->ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(*sockfd, SIOCGIFHWADDR, ifr) < 0) {
            log_error_errno("packet_socket", "SIOCGIFHWADDR");
            deinit_packet_socket(sockfd);
            return -1;
        }
    } else {
        memset(ifr, 0, sizeof(*ifr));
    }

    memset(bind_addr, 0, sizeof(*bind_addr));
    bind_addr->sll_family = AF_PACKET;
    bind_addr->sll_protocol = htons(ETHER_TYPE_CUSTOM);
    bind_addr->sll_ifindex = ifindex;

    if (bind(*sockfd, (struct sockaddr *)bind_addr, sizeof(*bind_addr)) < 0) {
        log_error_errno("packet_socket", "bind");
        deinit_packet_socket(sockfd);
        return -1;
    }

    return 0;
}

void deinit_packet_socket(int *sockfd) {
    if (!sockfd || *sockfd < 0) return;
    close(*sockfd);
    *sockfd = -1;
}

int l2s_send_frame_to_socket(int sockfd, const struct sockaddr_ll *dst,
                             const l2s_frame_meta_t *meta, const void *payload,
                             size_t payload_len, const char *debug_prefix) {
    if (sockfd < 0 || !dst || !meta)
        return -1;

    pack_t packet = {0};
    int frame_len = l2s_build_frame(&packet, sizeof(packet), meta, payload, payload_len);
    if (frame_len < 0)
        return frame_len;

    if (debug_prefix)
        debug_dump_frame(debug_prefix, (const u8 *)&packet, (size_t)frame_len);

    ssize_t sent = sendto(sockfd, &packet, (size_t)frame_len, 0,
                          (const struct sockaddr *)dst, sizeof(*dst));
    if (sent < 0 || (size_t)sent != (size_t)frame_len)
        return -1;

    return frame_len;
}

ssize_t l2s_write_all(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t remaining = count;
    ssize_t written = 0;

    while (remaining > 0) {
        written = write(fd, ptr, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return (ssize_t)(count - remaining);
        ptr += written;
        remaining -= (size_t)written;
    }

    return (ssize_t)count;
}
