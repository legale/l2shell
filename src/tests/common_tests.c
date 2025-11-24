#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "common.h"
#include "frame_dedup.h"
#include "test_common_shared.h"
#include "test_util.h"

static void test_hello_build_and_parse(void) {
    PRINT_TEST_START("hello_build_and_parse");
    u8 payload[MAX_PAYLOAD_SIZE] = {0};
    const char *spawn = "/usr/local/bin/a eth0";
    const char *shell = "sh -c test";
    hello_builder_t builder = {
        .spawn_cmd = spawn,
        .shell_cmd = shell,
        .nonce = 0x1122334455667788ULL,
        .include_spawn = 1,
        .include_nonce = 1,
    };

    int len = hello_build(payload, sizeof(payload), &builder);
    TEST_ASSERT(len > 0);

    hello_view_t view;
    TEST_ASSERT(hello_parse(payload, (size_t)len, &view) == 0);
    TEST_ASSERT(view.server_started);
    TEST_ASSERT(view.server_bin_path_len == strlen(spawn));
    TEST_ASSERT_MEMEQ(view.server_bin_path, spawn, view.server_bin_path_len);
    TEST_ASSERT(view.shell_started);
    TEST_ASSERT(view.cmd_len == strlen(shell));
    TEST_ASSERT_MEMEQ(view.cmd, shell, view.cmd_len);
    TEST_ASSERT(view.have_nonce);
    TEST_ASSERT(view.nonce == builder.nonce);
    PRINT_TEST_PASSED();
}

static void test_hello_build_without_spawn(void) {
    PRINT_TEST_START("hello_build_without_spawn");
    u8 payload[MAX_PAYLOAD_SIZE] = {0};
    const char *shell = "sh";
    hello_builder_t builder = {
        .spawn_cmd = NULL,
        .shell_cmd = shell,
        .nonce = 0xA5,
        .include_spawn = 0,
        .include_nonce = 1,
    };
    int len = hello_build(payload, sizeof(payload), &builder);
    TEST_ASSERT(len > 0);

    hello_view_t view;
    TEST_ASSERT(hello_parse(payload, (size_t)len, &view) == 0);
    TEST_ASSERT(!view.server_started);
    TEST_ASSERT(view.shell_started);
    TEST_ASSERT(view.cmd_len == strlen(shell));
    TEST_ASSERT(view.have_nonce);
    TEST_ASSERT(view.nonce == builder.nonce);
    PRINT_TEST_PASSED();
}

static void test_hello_timeout_tlv(void) {
    PRINT_TEST_START("hello_timeout_tlv");
    u8 payload[MAX_PAYLOAD_SIZE] = {0};
    hello_builder_t builder = {
        .shell_cmd = "test-cmd",
        .include_idle_timeout = 1,
        .idle_timeout_seconds = 45,
    };
    int len = hello_build(payload, sizeof(payload), &builder);
    TEST_ASSERT(len > 0);

    hello_view_t view;
    TEST_ASSERT(hello_parse(payload, (size_t)len, &view) == 0);
    TEST_ASSERT(view.have_idle_timeout);
    TEST_ASSERT(view.idle_timeout_seconds == 45);
    PRINT_TEST_PASSED();
}

static void test_hello_parse_rejects_bad_version(void) {
    PRINT_TEST_START("hello_parse_rejects_bad_version");
    u8 payload[1] = {HELLO_VERSION + 1};
    hello_view_t view;
    TEST_ASSERT(hello_parse(payload, sizeof(payload), &view) < 0);
    PRINT_TEST_PASSED();
}

static void test_hello_parse_rejects_truncated_tlv(void) {
    PRINT_TEST_START("hello_parse_rejects_truncated_tlv");
    u8 payload[4] = {HELLO_VERSION, HELLO_T_SHELL, 0x00, 0x04};
    hello_view_t view;
    TEST_ASSERT(hello_parse(payload, sizeof(payload), &view) < 0);
    PRINT_TEST_PASSED();
}

static void test_enc_dec_roundtrip(void) {
    PRINT_TEST_START("enc_dec_roundtrip");
    u8 plain[64];
    u8 encrypted[64];
    u8 decrypted[64];
    u32 key = 0x12345678;

    test_fill_payload(plain, sizeof(plain));
    enc_dec(plain, encrypted, (const u8 *)&key, sizeof(plain));
    enc_dec(encrypted, decrypted, (const u8 *)&key, sizeof(plain));

    TEST_ASSERT_MEMEQ(plain, decrypted, sizeof(plain));
    TEST_ASSERT_MEMNEQ(plain, encrypted, sizeof(plain));
    PRINT_TEST_PASSED();
}

static void test_build_and_parse_packet(void) {
    PRINT_TEST_START("build_and_parse_packet");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *message = "ping_over_l2shell";
    size_t payload_len = strlen(message);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, message, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, SERVER_SIGNATURE);
    TEST_ASSERT(frame_len > 0);

    pack_t checksum_probe = {0};
    memcpy(&checksum_probe, &packet, (size_t)frame_len);
    if (payload_len > 0) {
        u8 *nonce_ptr = checksum_probe.payload;
        u8 *data_ptr = checksum_probe.payload + PACKET_NONCE_LEN;
        enc_dec(data_ptr, data_ptr, (u8 *)&checksum_probe.header.crc, payload_len);
        (void)nonce_ptr;
    }
    checksum_probe.header.crc = 0;
    u32 expected_crc = csum32((const u8 *)&checksum_probe, (size_t)frame_len);
    TEST_ASSERT_EQ(ntohl(packet.header.crc), expected_crc);

    pack_t parsed = {0};
    memcpy(&parsed, &packet, (size_t)frame_len);
    int parsed_len = parse_packet(&parsed, frame_len, SERVER_SIGNATURE);
    TEST_ASSERT_EQ(parsed_len, (int)payload_len);
    TEST_ASSERT_MEMEQ(parsed.payload, message, payload_len);
    PRINT_TEST_PASSED();
}

static void test_build_packet_preserves_padding(void) {
    PRINT_TEST_START("build_packet_preserves_padding");
    pack_t packet;
    memset(&packet, 0xAA, sizeof(packet));
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *payload = "pad";
    size_t payload_len = strlen(payload);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, payload, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len > 0);

    TEST_ASSERT(packet.payload[PACKET_NONCE_LEN + payload_len] == (u8)0xAA);
    TEST_ASSERT(packet.payload[MAX_PAYLOAD_SIZE - 1] == (u8)0xAA);
    PRINT_TEST_PASSED();
}

static void test_parse_rejects_signature_mismatch(void) {
    PRINT_TEST_START("parse_rejects_signature_mismatch");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *message = "mismatch";
    size_t payload_len = strlen(message);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, message, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, SERVER_SIGNATURE);
    TEST_ASSERT(frame_len > 0);
    TEST_ASSERT(parse_packet(&packet, frame_len, CLIENT_SIGNATURE) < 0);
    PRINT_TEST_PASSED();
}

static void test_frame_dedup_same_iface(void) {
    PRINT_TEST_START("frame_dedup_same_iface");
    frame_dedup_entry_t slots[4];
    frame_dedup_cache_t cache = {0};
    frame_dedup_init(&cache, slots, ARRAY_SIZE(slots));

    u64 now = 1000;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 60, 0x1234, 7, now, 10000, NULL, NULL) == 0);
    now += 50;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 60, 0x1234, 7, now, 10000, NULL, NULL) == 0);
    PRINT_TEST_PASSED();
}

static void test_frame_dedup_different_iface_drop(void) {
    PRINT_TEST_START("frame_dedup_different_iface_drop");
    frame_dedup_entry_t slots[4];
    frame_dedup_cache_t cache = {0};
    frame_dedup_init(&cache, slots, ARRAY_SIZE(slots));

    u64 now = 500;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 80, 0x7777, 2, now, 10000, NULL, NULL) == 0);
    int prev_ifindex = 0;
    u64 age_ns = 0;
    now += 25;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 80, 0x7777, 9, now, 10000, &prev_ifindex, &age_ns) == 1);
    TEST_ASSERT(prev_ifindex == 2);
    TEST_ASSERT(age_ns == 25);
    PRINT_TEST_PASSED();
}

static void test_frame_dedup_expired_entry(void) {
    PRINT_TEST_START("frame_dedup_expired_entry");
    frame_dedup_entry_t slots[2];
    frame_dedup_cache_t cache = {0};
    frame_dedup_init(&cache, slots, ARRAY_SIZE(slots));

    u64 now = 0;
    const u64 window_ns = 10;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 32, 0x5555, 3, now, window_ns, NULL, NULL) == 0);
    now += window_ns + 5;
    TEST_ASSERT(frame_dedup_should_drop(&cache, 32, 0x5555, 4, now, window_ns, NULL, NULL) == 0);
    PRINT_TEST_PASSED();
}

static void test_frame_dedup_null_cache(void) {
    PRINT_TEST_START("frame_dedup_null_cache");
    TEST_ASSERT(frame_dedup_should_drop(NULL, 1, 1, 1, 0, 1, NULL, NULL) == 0);
    PRINT_TEST_PASSED();
}

static void test_build_packet_rejects_large_payload(void) {
    PRINT_TEST_START("build_packet_rejects_large_payload");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];

    test_set_macs(src_mac, dst_mac);
    int rc = build_packet(&packet, MAX_DATA_SIZE + 1U, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(rc < 0);
    PRINT_TEST_PASSED();
}

static void test_parse_packet_detects_crc_mismatch(void) {
    PRINT_TEST_START("parse_packet_detects_crc_mismatch");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *payload = "crc_mismatch";
    size_t payload_len = strlen(payload);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, payload, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len > 0);
    packet.payload[0] ^= 0xff;

    int rc = parse_packet(&packet, frame_len, CLIENT_SIGNATURE);
    TEST_ASSERT(rc < 0);
    PRINT_TEST_INFO("error is expected");
    PRINT_TEST_PASSED();
}

static void test_parse_packet_rejects_length_mismatch(void) {
    PRINT_TEST_START("parse_packet_rejects_length_mismatch");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *payload = "length-check";
    size_t payload_len = strlen(payload);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, payload, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len > 0);
    packet.header.payload_size = htonl((u32)(payload_len + 4));

    int rc = parse_packet(&packet, frame_len, CLIENT_SIGNATURE);
    TEST_ASSERT(rc < 0);
    PRINT_TEST_INFO("error is expected");
    PRINT_TEST_PASSED();
}

static void test_build_packet_null_args(void) {
    PRINT_TEST_START("build_packet_null_args");
    pack_t packet = {0};
    u8 mac[ETH_ALEN] = {0};
    TEST_ASSERT(build_packet(NULL, 0, mac, mac, CLIENT_SIGNATURE) < 0);
    TEST_ASSERT(build_packet(&packet, 0, NULL, mac, CLIENT_SIGNATURE) < 0);
    TEST_ASSERT(build_packet(&packet, 0, mac, NULL, CLIENT_SIGNATURE) < 0);
    PRINT_TEST_PASSED();
}

static void test_build_packet_sets_fields(void) {
    PRINT_TEST_START("build_packet_sets_fields");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char payload[] = {0x11, 0x22, 0x33, 0x44, 0x55};
    size_t payload_len = sizeof(payload);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, payload, payload_len);

    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len == (int)(sizeof(packh_t) + payload_len + PACKET_NONCE_LEN));
    TEST_ASSERT(ntohs(packet.header.eth_hdr.ether_type) == ETHER_TYPE_CUSTOM);
    TEST_ASSERT_MEMEQ(packet.header.eth_hdr.ether_shost, src_mac, ETH_ALEN);
    TEST_ASSERT_MEMEQ(packet.header.eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
    TEST_ASSERT(ntohl(packet.header.signature) == (u32)CLIENT_SIGNATURE);
    TEST_ASSERT(ntohl(packet.header.payload_size) == (u32)(payload_len + PACKET_NONCE_LEN));

    pack_t decrypted = packet;
    u8 *nonce_ptr = decrypted.payload;
    u8 *data_ptr = decrypted.payload + PACKET_NONCE_LEN;
    enc_dec(data_ptr, data_ptr, (u8 *)&packet.header.crc, payload_len);
    if (payload_len > 0) {
        enc_dec(data_ptr, data_ptr, l2s_shared_key, payload_len);
        for (size_t i = 0; i < payload_len; i++)
            data_ptr[i] ^= nonce_ptr[i & (PACKET_NONCE_LEN - 1)];
    }
    TEST_ASSERT_MEMEQ(data_ptr, payload, payload_len);
    PRINT_TEST_PASSED();
}

static void test_parse_packet_rejects_wrong_ethertype(void) {
    PRINT_TEST_START("parse_packet_rejects_wrong_ethertype");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    test_set_macs(src_mac, dst_mac);

    int frame_len = build_packet(&packet, 0, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len > 0);
    packet.header.eth_hdr.ether_type = htons(0x0800);
    TEST_ASSERT(parse_packet(&packet, frame_len, CLIENT_SIGNATURE) < 0);
    PRINT_TEST_PASSED();
}

static void test_parse_packet_rejects_truncated(void) {
    PRINT_TEST_START("parse_packet_rejects_truncated");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    const char *payload = "truncate";
    size_t payload_len = strlen(payload);

    test_set_macs(src_mac, dst_mac);
    memcpy(packet.payload, payload, payload_len);
    int frame_len = build_packet(&packet, payload_len, src_mac, dst_mac, CLIENT_SIGNATURE);
    TEST_ASSERT(frame_len > 0);
    PRINT_TEST_INFO("error is expected");
    TEST_ASSERT(parse_packet(&packet, frame_len - 1, CLIENT_SIGNATURE) < 0);
    PRINT_TEST_PASSED();
}

static void test_parse_packet_payload_too_large(void) {
    PRINT_TEST_START("parse_packet_payload_too_large");
    pack_t packet = {0};
    packet.header.eth_hdr.ether_type = htons(ETHER_TYPE_CUSTOM);
    packet.header.signature = htonl(CLIENT_SIGNATURE);
    packet.header.payload_size = htonl(MAX_PAYLOAD_SIZE + 1U);
    PRINT_TEST_INFO("error is expected");
    TEST_ASSERT(parse_packet(&packet, sizeof(packh_t), CLIENT_SIGNATURE) < 0);
    PRINT_TEST_PASSED();
}

static void test_l2s_send_frame_invalid_socket(void) {
    PRINT_TEST_START("l2s_send_frame_invalid_socket");
    struct sockaddr_ll dst = {0};
    dst.sll_family = AF_PACKET;
    dst.sll_protocol = htons(ETHER_TYPE_CUSTOM);
    dst.sll_halen = ETH_ALEN;
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    test_set_macs(src_mac, dst_mac);
    memcpy(dst.sll_addr, dst_mac, ETH_ALEN);

    l2s_frame_meta_t meta = {
        .src_mac = src_mac,
        .dst_mac = dst_mac,
        .signature = SERVER_SIGNATURE,
        .type = L2S_MSG_DATA,
        .flags = 0,
    };

    const char payload[] = "frame_test";
    int rc = l2s_send_frame_to_socket(-1, &dst, &meta, payload, sizeof(payload) - 1, "test_prefix");
    TEST_ASSERT(rc < 0);
    PRINT_TEST_PASSED();
}

static void test_l2s_write_all_pipe(void) {
    PRINT_TEST_START("l2s_write_all_pipe");
    int pipefd[2];
    TEST_ASSERT(pipe(pipefd) == 0);

    const size_t data_len = 64;
    u8 data[data_len];
    test_fill_payload(data, data_len);

    ssize_t written = l2s_write_all(pipefd[1], data, data_len);
    TEST_ASSERT_EQ(written, (ssize_t)data_len);

    u8 read_back[data_len];
    ssize_t got = read(pipefd[0], read_back, data_len);
    TEST_ASSERT_EQ(got, (ssize_t)data_len);
    TEST_ASSERT_MEMEQ(read_back, data, data_len);

    close(pipefd[0]);
    close(pipefd[1]);
    PRINT_TEST_PASSED();
}

static void test_debug_dump_frame_logs_prefix(void) {
    PRINT_TEST_START("debug_dump_frame_logs_prefix");
    const char *log_dir = "logs";
    const char *log_path = "logs/clientserver.log";
    (void)mkdir(log_dir, 0777);
    remove(log_path);

    u8 data[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    debug_dump_frame("test-prefix", data, sizeof(data));

    FILE *f = fopen(log_path, "r");
    if (!f) {
        char cwd[PATH_MAX] = {0};
        if (!getcwd(cwd, sizeof(cwd))) {
            strncpy(cwd, "<unknown>", sizeof(cwd) - 1);
        }
        fprintf(stderr, "fopen clientserver.log errno=%d cwd=%s\n", errno, cwd);
        fflush(stderr);
    }
    TEST_ASSERT(f != NULL);

    char line[128] = {0};
    TEST_ASSERT(fgets(line, sizeof(line), f) != NULL);
    fclose(f);

    TEST_ASSERT(strstr(line, "test-prefix") != NULL);
    TEST_ASSERT(strstr(line, "len=8") != NULL);
    PRINT_TEST_PASSED();
}

int main(int argc, char **argv) {
    const struct test_entry tests[] = {
        {"hello_build_and_parse", test_hello_build_and_parse},
        {"hello_build_without_spawn", test_hello_build_without_spawn},
        {"hello_timeout_tlv", test_hello_timeout_tlv},
        {"hello_parse_rejects_bad_version", test_hello_parse_rejects_bad_version},
        {"hello_parse_rejects_truncated_tlv", test_hello_parse_rejects_truncated_tlv},
        {"enc_dec_roundtrip", test_enc_dec_roundtrip},
        {"build_and_parse_packet", test_build_and_parse_packet},
        {"build_packet_preserves_padding", test_build_packet_preserves_padding},
        {"parse_rejects_signature_mismatch", test_parse_rejects_signature_mismatch},
        {"frame_dedup_same_iface", test_frame_dedup_same_iface},
        {"frame_dedup_different_iface_drop", test_frame_dedup_different_iface_drop},
        {"frame_dedup_expired_entry", test_frame_dedup_expired_entry},
        {"frame_dedup_null_cache", test_frame_dedup_null_cache},
        {"build_packet_rejects_large_payload", test_build_packet_rejects_large_payload},
        {"parse_packet_detects_crc_mismatch", test_parse_packet_detects_crc_mismatch},
        {"parse_packet_rejects_length_mismatch", test_parse_packet_rejects_length_mismatch},
        {"build_packet_null_args", test_build_packet_null_args},
        {"build_packet_sets_fields", test_build_packet_sets_fields},
        {"parse_packet_rejects_wrong_ethertype", test_parse_packet_rejects_wrong_ethertype},
        {"parse_packet_rejects_truncated", test_parse_packet_rejects_truncated},
        {"parse_packet_payload_too_large", test_parse_packet_payload_too_large},
        {"l2s_send_frame_invalid_socket", test_l2s_send_frame_invalid_socket},
        {"l2s_write_all_pipe", test_l2s_write_all_pipe},
        {"debug_dump_frame_logs_prefix", test_debug_dump_frame_logs_prefix},
    };

    const char *filter = (argc > 1) ? argv[1] : NULL;
    return run_named_test(filter, tests, ARRAY_SIZE(tests));
}
