#include <errno.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lz4.h"

static int emit_header(FILE *out, const unsigned char *data, size_t comp_len, size_t orig_len) {
    size_t col = 0;

    if (fprintf(out, "const unsigned char l2shell_embed[] = {\n") < 0)
        return -errno;
    for (size_t i = 0; i < comp_len; i++) {
        if (col == 0 && fputc('\t', out) == EOF)
            return -errno;
        if (fprintf(out, "0x%02x,", data[i]) < 0)
            return -errno;
        col++;
        if (col >= 12) {
            if (fputc('\n', out) == EOF)
                return -errno;
            col = 0;
        } else if (fputc(' ', out) == EOF) {
            return -errno;
        }
    }
    if (col && fputc('\n', out) == EOF)
        return -errno;
    if (fprintf(out,
                "};\nconst unsigned int l2shell_embed_len = %zu;\nconst unsigned int l2shell_embed_orig_len = %zu;\n",
                comp_len,
                orig_len) < 0)
        return -errno;
    return 0;
}

int main(int argc, char **argv) {
    FILE *in = NULL;
    FILE *out = NULL;
    unsigned char *input = NULL;
    unsigned char *compressed = NULL;
    size_t orig_size;
    size_t comp_capacity;
    int comp_len;
    int rc = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    in = fopen(argv[1], "rb");
    if (!in) {
        perror("input");
        goto out;
    }

    out = fopen(argv[2], "w");
    if (!out) {
        perror("output");
        goto out;
    }

    if (fseek(in, 0, SEEK_END) < 0) {
        perror("seek");
        goto out;
    }
    long sz = ftell(in);
    if (sz < 0) {
        perror("ftell");
        goto out;
    }
    if (fseek(in, 0, SEEK_SET) < 0) {
        perror("seek");
        goto out;
    }
    orig_size = (size_t)sz;
    input = malloc(orig_size);
    if (!input) {
        perror("malloc input");
        goto out;
    }
    if (fread(input, 1, orig_size, in) != orig_size) {
        perror("fread input");
        goto out;
    }

    comp_capacity = lz4_compress_bound(orig_size);
    compressed = malloc(comp_capacity);
    if (!compressed) {
        perror("malloc compressed");
        goto out;
    }

    comp_len = lz4_compress_default(input, orig_size, compressed, comp_capacity);
    if (comp_len <= 0) {
        fprintf(stderr, "bin2c: compression failed\n");
        goto out;
    }

    {
        unsigned char *verify = malloc(orig_size);
        if (!verify) {
            perror("malloc verify");
            goto out;
        }
        int dec = lz4_decompress_safe(compressed, (size_t)comp_len, verify, orig_size);
        if (dec < 0 || (size_t)dec != orig_size) {
            fprintf(stderr, "bin2c: verification failed\n");
            free(verify);
            goto out;
        }
        if (memcmp(verify, input, orig_size) != 0) {
            fprintf(stderr, "bin2c: verify mismatch\n");
            free(verify);
            goto out;
        }
        free(verify);
    }

    if (emit_header(out, compressed, (size_t)comp_len, orig_size) != 0) {
        perror("bin2c emit");
        goto out;
    }

    rc = 0;

out:
    if (in && fclose(in))
        perror("fclose input");
    if (out && fclose(out))
        perror("fclose output");
    free(input);
    free(compressed);

    return rc;
}
