#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int emit_header(FILE *out, FILE *in) {
    unsigned char buf[256];
    size_t total = 0;
    int col = 0;
    long size;

    if (fseek(in, 0, SEEK_END) < 0)
        return -errno;
    size = ftell(in);
    if (size < 0)
        return -errno;
    if (fseek(in, 0, SEEK_SET) < 0)
        return -errno;

    if (fprintf(out, "const unsigned char l2shell_embed[] = {\n") < 0)
        return -errno;

    for (;;) {
        size_t got = fread(buf, 1, sizeof(buf), in);
        if (got == 0) {
            if (ferror(in))
                return -errno;
            break;
        }
        for (size_t i = 0; i < got; i++) {
            if (col == 0)
                fprintf(out, "\t");
            if (fprintf(out, "0x%02x,", buf[i]) < 0)
                return -errno;
            col++;
            total++;
            if (col >= 12) {
                if (fputc('\n', out) == EOF)
                    return -errno;
                col = 0;
            } else {
                fputc(' ', out);
            }
        }
    }

    if (col != 0 && fputc('\n', out) == EOF)
        return -errno;
    if (fprintf(out, "};\nconst unsigned int l2shell_embed_len = %zu;\n", (size_t)size) < 0)
        return -errno;

    if ((size_t)size != total)
        return -EIO;
    return 0;
}

int main(int argc, char **argv) {
    FILE *in = NULL;
    FILE *out = NULL;
    int rc = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    in = fopen(argv[1], "rb");
    if (!in) {
        perror("fopen input");
        goto out;
    }

    out = fopen(argv[2], "w");
    if (!out) {
        perror("fopen output");
        goto out;
    }

    if (emit_header(out, in) == 0)
        rc = 0;
    else
        perror("bin2c");

out:
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    return rc;
}
