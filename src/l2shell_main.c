#include <stdio.h>
#include <string.h>

int client_main(int argc, char **argv);
int server_main(int argc, char **argv);

static const char *strip_prog(const char *path) {
    if (!path) return "";
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int redirect_to_mode(const char *mode, int argc, char **argv, int skip) {
    if (skip) {
        argc--;
        argv++;
    }
    if (strcmp(mode, "client") == 0) {
        return client_main(argc, argv);
    } else {
        return server_main(argc, argv);
    }
}

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [server|client] [options]\n", prog);
    fprintf(stderr, "  or run via symlink 'a' or 'b' to force mode\n");
}

int main(int argc, char **argv) {
    const char *prog = strip_prog(argv[0]);
    const char *mode = NULL;
    int skip = 0;

    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) {
            mode = "client";
            skip = 1;
        } else if (strcmp(argv[1], "server") == 0) {
            mode = "server";
            skip = 1;
        }
    }

    if (!mode) {
        if (strcmp(prog, "a") == 0 || strcmp(prog, "server") == 0)
            mode = "server";
        else if (strcmp(prog, "b") == 0 || strcmp(prog, "client") == 0)
            mode = "client";
        else {
            usage(prog);
            return 1;
        }
    }

    return redirect_to_mode(mode, argc, argv, skip);
}
