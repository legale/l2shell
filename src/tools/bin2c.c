#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int emit_header(FILE *out, FILE *in) {
    unsigned char buf[256];
    size_t total = 0, got, i;
    int col = 0;

    if (fprintf(out, "const unsigned char l2shell_embed[] = {\n") < 0) return -errno;

    while ((got = fread(buf, 1, sizeof(buf), in)) > 0) {
        for (i = 0; i < got; i++) {
            if (!col && fputc('\t', out) == EOF) return -errno; // indent
            if (fprintf(out, "0x%02x,", buf[i]) < 0) return -errno; // payload byte
            total++;
            if (++col >= 12) { // 12 bytes per line
                if (fputc('\n', out) == EOF) return -errno; // newline
                col = 0;
            } else if (fputc(' ', out) == EOF) // space
                return -errno;
        }
    }

    if (ferror(in)) return -errno;
    if (col && fputc('\n', out) == EOF) return -errno;
    if (fprintf(out, "};\nconst unsigned int l2shell_embed_len = %zu;\n", total) < 0) return -errno;

    return 0;
}

int main(int argc, char **argv) {
    FILE *in, *out;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    in = fopen(argv[1], "rb");
    if (!in) {
        perror("input");
        return 1;
    }

    out = fopen(argv[2], "w");
    if (!out) {
        perror("output");
        fclose(in);
        return 1;
    }

    rc = emit_header(out, in);
    if (rc) {
        errno = -rc;
        perror("bin2c");
    }

    if (fclose(in)) perror("fclose input");
    if (fclose(out)) perror("fclose output");

    return rc ? 1 : 0;
}