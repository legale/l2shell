#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "common.h"
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

static void test_hello_parse_rejects_bad_version(void) {
    PRINT_TEST_START("hello_parse_rejects_bad_version");
    u8 payload[1] = {HELLO_VERSION + 1};
    hello_view_t view;
    PRINT_TEST_INFO("error is expected");
    TEST_ASSERT(hello_parse(payload, sizeof(payload), &view) < 0);
    PRINT_TEST_PASSED();
}

static void test_hello_parse_rejects_truncated_tlv(void) {
    PRINT_TEST_START("hello_parse_rejects_truncated_tlv");
    u8 payload[4] = {HELLO_VERSION, HELLO_T_SHELL, 0x00, 0x04};
    hello_view_t view;
    PRINT_TEST_INFO("error is expected");
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
        enc_dec(checksum_probe.payload, checksum_probe.payload, (u8 *)&checksum_probe.header.crc, payload_len);
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

    TEST_ASSERT(packet.payload[payload_len] == (u8)0xAA);
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

static void test_packet_dedup_cache(void) {
    PRINT_TEST_START("packet_dedup_cache");
    packet_dedup_t cache;
    u8 mac[ETH_ALEN] = {0x02, 0xff, 0xee, 0xdd, 0xcc, 0xbb};
    packet_dedup_init(&cache);

    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0xdeadbeef, 10, CLIENT_SIGNATURE, PACKET_DEDUP_WINDOW_NS) == 0);
    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0xdeadbeef, 10, CLIENT_SIGNATURE, PACKET_DEDUP_WINDOW_NS) == 1);
    PRINT_TEST_PASSED();
}

static void test_build_packet_rejects_large_payload(void) {
    PRINT_TEST_START("build_packet_rejects_large_payload");
    pack_t packet = {0};
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];

    test_set_macs(src_mac, dst_mac);
    int rc = build_packet(&packet, MAX_PAYLOAD_SIZE + 1U, src_mac, dst_mac, CLIENT_SIGNATURE);
    PRINT_TEST_INFO("error is expected");
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

static void test_dedup_accepts_different_crc(void) {
    PRINT_TEST_START("dedup_accepts_different_crc");
    packet_dedup_t cache;
    u8 mac[ETH_ALEN] = {0x02, 0xff, 0x00, 0x00, 0x00, 0x04};
    packet_dedup_init(&cache);

    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0xaaaaaaaa, 4, CLIENT_SIGNATURE, PACKET_DEDUP_WINDOW_NS) == 0);
    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0xbbbbbbbb, 4, CLIENT_SIGNATURE, PACKET_DEDUP_WINDOW_NS) == 0);
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
    TEST_ASSERT(frame_len == (int)(sizeof(packh_t) + payload_len));
    TEST_ASSERT(ntohs(packet.header.eth_hdr.ether_type) == ETHER_TYPE_CUSTOM);
    TEST_ASSERT_MEMEQ(packet.header.eth_hdr.ether_shost, src_mac, ETH_ALEN);
    TEST_ASSERT_MEMEQ(packet.header.eth_hdr.ether_dhost, dst_mac, ETH_ALEN);
    TEST_ASSERT(ntohl(packet.header.signature) == (u32)CLIENT_SIGNATURE);
    TEST_ASSERT(ntohl(packet.header.payload_size) == (u32)payload_len);

    pack_t decrypted = packet;
    enc_dec(decrypted.payload, decrypted.payload, (u8 *)&packet.header.crc, payload_len);
    if (payload_len > 0) {
        u32 zero_key = 0;
        enc_dec(decrypted.payload, decrypted.payload, (u8 *)&zero_key, payload_len);
    }
    TEST_ASSERT_MEMEQ(decrypted.payload, payload, payload_len);
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

static void test_dedup_expired_entry(void) {
    PRINT_TEST_START("dedup_expired_entry");
    packet_dedup_t cache;
    u8 mac[ETH_ALEN] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x01};
    packet_dedup_init(&cache);

    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0x1234, 8, CLIENT_SIGNATURE, 1) == 0);
    packet_fingerprint_t *entry = &cache.entries[0];
    entry->ts.tv_sec = 0;
    entry->ts.tv_nsec = 0;
    entry->valid = 1;
    TEST_ASSERT(packet_dedup_handler(&cache, mac, 0x1234, 8, CLIENT_SIGNATURE, 1) == 0);
    PRINT_TEST_PASSED();
}

static void test_dedup_null_args(void) {
    PRINT_TEST_START("dedup_null_args");
    u8 mac[ETH_ALEN] = {0};
    TEST_ASSERT(packet_dedup_handler(NULL, mac, 0, 0, 0, 0) == 0);
    TEST_ASSERT(packet_dedup_handler(&(packet_dedup_t){0}, NULL, 0, 0, 0, 0) == 0);
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
        {"hello_parse_rejects_bad_version", test_hello_parse_rejects_bad_version},
        {"hello_parse_rejects_truncated_tlv", test_hello_parse_rejects_truncated_tlv},
        {"enc_dec_roundtrip", test_enc_dec_roundtrip},
        {"build_and_parse_packet", test_build_and_parse_packet},
        {"build_packet_preserves_padding", test_build_packet_preserves_padding},
        {"parse_rejects_signature_mismatch", test_parse_rejects_signature_mismatch},
        {"packet_dedup_cache", test_packet_dedup_cache},
        {"build_packet_rejects_large_payload", test_build_packet_rejects_large_payload},
        {"parse_packet_detects_crc_mismatch", test_parse_packet_detects_crc_mismatch},
        {"parse_packet_rejects_length_mismatch", test_parse_packet_rejects_length_mismatch},
        {"dedup_accepts_different_crc", test_dedup_accepts_different_crc},
        {"build_packet_null_args", test_build_packet_null_args},
        {"build_packet_sets_fields", test_build_packet_sets_fields},
        {"parse_packet_rejects_wrong_ethertype", test_parse_packet_rejects_wrong_ethertype},
        {"parse_packet_rejects_truncated", test_parse_packet_rejects_truncated},
        {"parse_packet_payload_too_large", test_parse_packet_payload_too_large},
        {"dedup_expired_entry", test_dedup_expired_entry},
        {"dedup_null_args", test_dedup_null_args},
        {"debug_dump_frame_logs_prefix", test_debug_dump_frame_logs_prefix},
    };

    const char *filter = (argc > 1) ? argv[1] : NULL;
    return run_named_test(filter, tests, ARRAY_SIZE(tests));
}
