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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h> //difftime
#include <unistd.h>

#define L2SHELL_DEFAULT_CMD "login"
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

static pid_t start_shell_proc(const char *command);
static void terminate_shell_process(void);
static int server_exec(server_ctx_t *ctx, const u8 *payload,
                       size_t payload_size);
static int check_shell_termination(server_ctx_t *ctx);
static void usage(const char *prog);
static void server_format_ifname(int ifindex, char buf[IFNAMSIZ]);
static u32 server_frame_fingerprint(const l2s_frame_t *packet, size_t len);
static int server_frame_dedup_should_drop(const l2s_frame_t *packet, size_t len,
                                          const struct sockaddr_ll *peer);
static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload,
                                        size_t payload_size,
                                        const struct sockaddr_ll *peer);
static int server_hello_handler(server_ctx_t *ctx, const u8 *payload,
                                size_t payload_size,
                                const struct sockaddr_ll *peer);
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
  int idle_timeout_sec;
};

static void server_send_tagged(server_ctx_t *ctx, const char *tag,
                               const char *fmt, ...) {
  char message[MAX_DATA_SIZE];
  va_list ap;
  int prefix_len;
  int payload_len;
  l2s_frame_t packet;
  int frame_len;
  l2s_frame_meta_t meta;

  if (!ctx || ctx->sockfd < 0 || !fmt)
    return;

  prefix_len = snprintf(message, sizeof(message), "level=info tag=%s ",
                        tag ? tag : "server");
  if (prefix_len < 0 || prefix_len >= (int)sizeof(message))
    return;

  va_start(ap, fmt);
  payload_len = vsnprintf(message + prefix_len,
                          sizeof(message) - (size_t)prefix_len, fmt, ap);
  va_end(ap);
  if (payload_len < 0)
    return;
  payload_len += prefix_len;
  if (payload_len >= (int)sizeof(message))
    payload_len = (int)sizeof(message) - 1;
  message[payload_len++] = '\n';

  if (payload_len <= 0)
    return;
  memcpy(packet.payload, message, (size_t)payload_len);
  meta.src_mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data;
  meta.dst_mac = (u8 *)ctx->peer_addr.sll_addr;
  meta.signature = SERVER_SIGNATURE;
  meta.type = L2S_MSG_CONTROL;
  meta.flags = 0;

  frame_len = l2s_send_frame_to_socket(ctx->sockfd, &ctx->peer_addr, &meta,
                                       packet.payload, (size_t)payload_len,
                                       "server_tx status frame ");
  if (frame_len < 0) {
    log_error_errno("server_tx", "event=status_send");
  }
}

static void server_apply_idle_timeout(server_ctx_t *ctx, int seconds) {
  if (!ctx)
    return;
  int secs = seconds;
  if (secs <= 0)
    secs = SERVER_IDLE_TIMEOUT_DEFAULT_SEC;
  if (secs > SERVER_IDLE_TIMEOUT_MAX_SEC)
    secs = SERVER_IDLE_TIMEOUT_MAX_SEC;
  ctx->idle_timeout_sec = secs;
}

// Функция для обработки чтения данных от клиента и отправки их процессу сервера
static ssize_t server_read_raw_frame(server_ctx_t *ctx, l2s_frame_t *packet,
                                     struct sockaddr_ll *peer) {
  assert(ctx);
  assert(packet);
  assert(peer);
  if (ctx->sockfd < 0)
    return -1;

  socklen_t saddr_len = sizeof(struct sockaddr_ll);
  ssize_t ret = recvfrom(ctx->sockfd, packet, sizeof(l2s_frame_t), 0,
                         (struct sockaddr *)peer, &saddr_len);
  debug_dump_frame("server_rx frame", (const u8 *)packet, (size_t)ret);
  return ret;
}

static int server_update_iface_out(server_ctx_t *ctx,
                                   const struct sockaddr_ll *peer) {
  if (!ctx || !peer)
    return -1;
  if (!ctx->any_iface)
    return 0;

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

static int server_validate_mac(server_ctx_t *ctx,
                               const l2s_frame_header_t *header) {
  assert(ctx);
  assert(header);
  if (ctx->any_iface)
    return 0;
  if (memcmp(header->eth_hdr.ether_dhost, ctx->ifr.ifr_hwaddr.sa_data,
             ETH_ALEN) != 0)
    return -1;
  if (memcmp(header->eth_hdr.ether_shost, ctx->ifr.ifr_hwaddr.sa_data,
             ETH_ALEN) == 0)
    return -1;
  return 0;
}

static void server_send_ready_ack(server_ctx_t *ctx,
                                  const hello_view_t *hello) {
  char msg[128];
  size_t msg_len;
  l2s_frame_t packet;
  int frame_len;
  l2s_frame_meta_t meta;
  char ifname[IFNAMSIZ];

  if (!ctx || ctx->sockfd < 0 || !hello)
    return;

  if (hello->have_nonce) {
    msg_len = (size_t)snprintf(msg, sizeof(msg),
                               "ready nonce=%016llx source=userland\n",
                               (unsigned long long)hello->nonce);
  } else {
    msg_len = (size_t)snprintf(msg, sizeof(msg), "ready source=userland\n");
  }

  memcpy(packet.payload, msg, msg_len);

  meta.src_mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data;
  meta.dst_mac = (u8 *)ctx->peer_addr.sll_addr;
  meta.signature = SERVER_SIGNATURE;
  meta.type = L2S_MSG_CONTROL;
  meta.flags = 0;
  frame_len = l2s_send_frame_to_socket(ctx->sockfd, &ctx->peer_addr, &meta,
                                       packet.payload, msg_len,
                                       "server_tx ready ack frame ");
  if (frame_len < 0) {
    log_error_errno("server_ready", "sendto");
    return;
  }
  server_format_ifname(ctx->bind_addr.sll_ifindex, ifname);
  log_info("server_ready", "event=sent nonce=%016llx has_nonce=%d iface=%s",
           (unsigned long long)hello->nonce, hello->have_nonce, ifname);
}

static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload,
                                        size_t payload_size,
                                        const struct sockaddr_ll *peer);

static int server_cmd_exec_handler(server_ctx_t *ctx, l2s_frame_t *packet,
                                   int payload_size,
                                   const struct sockaddr_ll *peer) {
  assert(ctx);
  assert(packet);

  if (peer) {
    ctx->peer_addr = *peer;
    if (ctx->any_iface)
      (void)server_update_iface_out(ctx, peer);
  }

  if (payload_size > 0) {
    hello_view_t hello = {0};
    if (hello_parse(packet->payload, (size_t)payload_size, &hello) == 0 &&
        hello.shell_started && hello.cmd_len > 0) {
      if (hello.have_nonce) {
        ctx->pending_nonce = hello.nonce;
        ctx->awaiting_nonce_confirm = 1;
      } else {
        ctx->awaiting_nonce_confirm = 0;
      }
      if (hello.have_idle_timeout) {
        server_apply_idle_timeout(ctx, hello.idle_timeout_seconds);
      }
      if (server_exec(ctx, hello.cmd, hello.cmd_len) != 0) {
        log_error("server_launch", "event=hello_launch_failed");
      } else {
        server_send_ready_ack(ctx, &hello);
      }
      log_info("idle_timeout", "sec=%d", ctx->idle_timeout_sec);
      return payload_size;
    }
  }

  const u8 *cmd = (u8 *)L2SHELL_DEFAULT_CMD;
  size_t cmd_len = sizeof(L2SHELL_DEFAULT_CMD) - 1;

  log_info("server_launch_default", "%s", cmd);
  if (server_exec(ctx, cmd, cmd_len) != 0) {
    log_error("server_launch", "event=launch_failed");
  }
  return payload_size;
}

static int server_payload_handler(server_ctx_t *ctx, l2s_frame_t *packet,
                                  int payload_size,
                                  const struct sockaddr_ll *peer) {
  assert(ctx);
  assert(packet);
  if (server_nonce_confirm_handler(ctx, packet->payload, (size_t)payload_size,
                                   peer))
    return payload_size;
  if (sh_fd != -1 &&
      server_hello_handler(ctx, packet->payload, (size_t)payload_size, peer))
    return payload_size;
  if (sh_fd == -1)
    return server_cmd_exec_handler(ctx, packet, payload_size, peer);
  (void)l2s_write_all(sh_fd, packet->payload, (size_t)payload_size);
  return payload_size;
}

static ssize_t server_socket_event_handler(server_ctx_t *ctx,
                                           l2s_frame_t *packet) {
  struct sockaddr_ll peer = {0};
  ssize_t ret = server_read_raw_frame(ctx, packet, &peer);
  if (ret <= 0)
    return ret;

  if ((size_t)ret < sizeof(l2s_frame_header_t))
    return -1;

  l2s_frame_header_t *header = (l2s_frame_header_t *)packet;
  size_t payload_size = 0;
  int parse_rc;

  if (server_frame_dedup_should_drop(packet, (size_t)ret, &peer) != 0)
    return -1;

  char peer_ifname[IFNAMSIZ];
  server_format_ifname(peer.sll_ifindex, peer_ifname);

  if (server_validate_mac(ctx, header) != 0)
    return -1;

  u32 signature_host = ntohl(header->signature);
  u32 crc = ntohl(packet->header.crc);
  parse_rc =
      l2s_parse_frame(packet, (size_t)ret, CLIENT_SIGNATURE, &payload_size);
  if (parse_rc != L2S_FRAME_OK) {
    return -1;
  }

  log_info("server_rx",
           "b=%zd ether=0x%04x pay_sz=%u src=" MACSTR " dst=" MACSTR
           " sign=0x%04x csum=%u iface=%s",
           ret, ntohs(header->eth_hdr.ether_type), (unsigned int)payload_size,
           MAC2STR(header->eth_hdr.ether_shost),
           MAC2STR(header->eth_hdr.ether_dhost), signature_host, crc,
           peer_ifname);

  return server_payload_handler(ctx, packet, (int)payload_size, &peer);
}

static int server_exec(server_ctx_t *ctx, const u8 *payload,
                       size_t payload_size) {
  if (!ctx)
    return -1;
  if (payload_size == 0) {
    log_error("server_launch", "event=empty_payload");
    return -1;
  }
  static char command_buf[MAX_DATA_SIZE + 1];
  if (payload_size > sizeof(command_buf) - 1) {
    log_error("server_launch", "event=payload_overflow len=%zu", payload_size);
    return -1;
  }
  size_t writesz = MIN(sizeof(command_buf),
                       payload_size); // limit the size to prevent overflow
  memcpy(command_buf, payload, writesz);
  command_buf[writesz] = '\0';
  if (command_buf[0] == '\0') {
    log_error("server_launch", "event=payload_null");
    return -1;
  }
  if (start_shell_proc(command_buf) < 0)
    return -1;
  server_send_tagged(ctx, "server_shell", "event=started pid=%d cmd='%s'",
                     (int)pid, command_buf);
  return 0;
}

// Функция для обработки чтения и записи данных в клиент
static void server_handle_shell_event(server_ctx_t *ctx, l2s_frame_t *packet) {
  if (!ctx || ctx->sockfd < 0 || sh_fd < 0 || !packet)
    return;

  ssize_t ret = read(sh_fd, packet->payload, MAX_DATA_SIZE);

  // Проверка успешности чтения из sh_fd
  if (ret <= 0)
    return; // Если чтение не удалось, выходим

  l2s_frame_meta_t meta = {
      .src_mac = (u8 *)ctx->ifr.ifr_hwaddr.sa_data,
      .dst_mac = (u8 *)ctx->peer_addr.sll_addr,
      .signature = SERVER_SIGNATURE,
      .type = L2S_MSG_DATA,
      .flags = 0,
  };
  int frame_len = l2s_send_frame_to_socket(ctx->sockfd, &ctx->peer_addr, &meta,
                                           packet->payload, (size_t)ret,
                                           "server_tx frame ");
  if (frame_len < 0) {
    log_error_errno("server_tx", "event=sendto");
    return;
  }
}

static pid_t start_shell_proc(const char *command) {
  if (!command) {
    log_error("server_shell", "cmd=NULL");
    return -1;
  }
  pid_t child;
  log_info("server_shell", "forkpty execlp cmd='%s'", command);

  child = forkpty(&sh_fd, NULL, NULL, NULL);
  if (child < 0) {
    log_error_errno("server_shell", "forkpty");
    return -1;
  }

  // child process
  if (child == 0) {
    log_info("server_shell", "execlp pid=%d cmd='%s'", (int)getpid(), command);
    execlp(command, command, NULL);
    log_error_errno("server_shell", "execlp='%s'", command);
    _exit(1);
  }

  // parent process
  pid = child;
  log_info("server_shell", "started pid=%d cmd='%s'", (int)pid, command);
  return child;
}

// Проверяет, завершился ли процесс команды, и очищает ресурсы
static int check_shell_termination(server_ctx_t *ctx) {
  sig_atomic_t current_pid = pid; // Атомарное чтение
  if (current_pid == -1)
    return 0;

  int status;
  pid_t result = waitpid(current_pid, &status, WNOHANG);
  if (result != current_pid)
    return 0;

  int exit_code = -1;
  int term_sig = 0;
  if (WIFEXITED(status))
    exit_code = WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    term_sig = WTERMSIG(status);

  log_info("server_shell", "terminated pid=%d exit=%d signal=%d", current_pid,
           exit_code, term_sig);
  server_send_tagged(ctx, "server_shell",
                     "event=terminated pid=%d exit=%d signal=%d",
                     (int)current_pid, exit_code, term_sig);

  if (sh_fd != -1) {
    close(sh_fd);
    sh_fd = -1;
  }
  pid = -1;
  return 1;
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
  if (!args || !argv)
    return 1;
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
  if (!ctx || !args)
    return -1;
  ctx->sockfd = -1;
  ctx->any_iface = args->any_iface;

  const char *listen_iface = args->any_iface ? NULL : args->iface;
  if (init_packet_socket(&ctx->sockfd, &ctx->ifr, &ctx->bind_addr, listen_iface,
                         0) != 0) {
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
  if (!ctx)
    return;
  deinit_packet_socket(&ctx->sockfd);
}

static int server_loop(server_ctx_t *ctx) {
  if (!ctx || ctx->sockfd < 0)
    return -1;

  fd_set fds;
  l2s_frame_t rx_packet = {0};
  l2s_frame_t tx_packet = {0};
  time_t last_client_activity = time(NULL);

  for (;;) {
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    int max_fd = ctx->sockfd;
    int ready;

    FD_ZERO(&fds);
    FD_SET(ctx->sockfd, &fds);

    if (sh_fd != -1) {
      FD_SET(sh_fd, &fds);
      if (sh_fd > max_fd)
        max_fd = sh_fd;
    }

    ready = select(max_fd + 1, &fds, NULL, NULL, &tv);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      log_error_errno("server_loop", "select");
      return -1;
    }

    if (check_shell_termination(ctx)) {
      log_info("server_loop", "event=shell_finished exiting=1");
      server_send_tagged(ctx, "server_shell", "event=server_exit");
      break;
    }

    if (ready > 0) {
      if (sh_fd != -1 && FD_ISSET(sh_fd, &fds)) {
        server_handle_shell_event(ctx, &tx_packet);
      }

      if (FD_ISSET(ctx->sockfd, &fds)) {
        if (server_socket_event_handler(ctx, &rx_packet) >= 0) {
          last_client_activity = time(NULL);
          continue; // skip idle timeout check
        }
      }
    }

    time_t now = time(NULL);
    if ((now - last_client_activity) >= ctx->idle_timeout_sec) {
      log_info("server_loop", "event=idle_timeout timeout=%d",
               ctx->idle_timeout_sec);
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
  if (pr != 0)
    return pr > 0 ? 0 : 1;
  if (args.log_path && log_redirect_stdio(args.log_path) != 0) {
    log_error_errno("server_args", "event=log_file_open path=%s",
                    args.log_path);
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
  fprintf(stderr, "Usage: %s [--log-file <path>] <interface|any> [--help]\n",
          prog);
}

static void server_format_ifname(int ifindex, char buf[IFNAMSIZ]) {
  if (!buf)
    return;
  if (ifindex > 0 && if_indextoname((unsigned int)ifindex, buf))
    return;
  buf[0] = '?';
  buf[1] = '\0';
}

static u32 server_frame_fingerprint(const l2s_frame_t *packet, size_t len) {
  if (!packet || len < sizeof(l2s_frame_header_t))
    return 0;
  const l2s_frame_header_t *h = &packet->header;
  u32 crc = ntohl(h->crc);
  u32 sig = ntohl(h->signature);
  u32 psz = ntohl(h->payload_size);
  return crc ^ sig ^ psz;
}

// Проверяет, следует ли отбросить дубликат фрейма
static int server_frame_dedup_should_drop(const l2s_frame_t *packet, size_t len,
                                          const struct sockaddr_ll *peer) {
  if (!packet || len == 0)
    return 0;
  const u64 now = l2s_mono_ns();
  const u32 checksum = server_frame_fingerprint(packet, len);
  const int cur_ifindex = peer ? peer->sll_ifindex : 0;
  char cur_ifname[IFNAMSIZ];
  int prev_ifindex = 0;
  u64 age_ns = 0;

  server_format_ifname(cur_ifindex, cur_ifname);
  if (!frame_dedup_should_drop(&server_dedup, len, checksum, cur_ifindex, now,
                               SERVER_DUP_WINDOW_NS, &prev_ifindex, &age_ns)) {
    return 0;
  }

  char prev_ifname[IFNAMSIZ];
  server_format_ifname(prev_ifindex, prev_ifname);
  log_info("server_dup",
           "event=drop len=%zu age_ns=%llu checksum=%u iface=%s prev_iface=%s",
           len, (unsigned long long)age_ns, checksum, cur_ifname, prev_ifname);
  return -1;
}

// обработчик подтверждения nonce от клиента
static int server_nonce_confirm_handler(server_ctx_t *ctx, const u8 *payload,
                                        size_t payload_size,
                                        const struct sockaddr_ll *peer) {
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
  server_format_ifname(peer ? peer->sll_ifindex : ctx->bind_addr.sll_ifindex,
                       ifname);
  log_info("server_handshake", "event=nonce_confirmed nonce=%016llx iface=%s",
           (unsigned long long)ctx->pending_nonce, ifname);
  return 1;
}

static int server_hello_handler(server_ctx_t *ctx, const u8 *payload,
                                size_t payload_size,
                                const struct sockaddr_ll *peer) {
  if (!ctx || !payload || payload_size == 0)
    return 0;

  hello_view_t hello = {0};
  if (hello_parse(payload, payload_size, &hello) != 0)
    return 0;

  if (peer) {
    ctx->peer_addr = *peer;
    if (ctx->any_iface)
      (void)server_update_iface_out(ctx, peer);
  }

  if (hello.have_heartbeat) {
    char ifname[IFNAMSIZ];
    server_format_ifname(peer ? peer->sll_ifindex : ctx->bind_addr.sll_ifindex,
                         ifname);
    log_info("server_heartbeat", "event=received iface=%s", ifname);
    return 1;
  }

  if (!hello.shell_started || hello.cmd_len == 0)
    return 0;

  if (hello.have_nonce) {
    ctx->pending_nonce = hello.nonce;
    ctx->awaiting_nonce_confirm = 1;
  } else {
    ctx->awaiting_nonce_confirm = 0;
  }

  server_send_ready_ack(ctx, &hello);
  log_info("server_hello", "event=resume shell_running=%d",
           sh_fd != -1 ? 1 : 0);
  return 1;
}
