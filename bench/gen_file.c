/**
 * Generates random file of random size
 * @author Judicael Djoko
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int get_mult(char c) {
    switch (c) {
        case 'k':
        case 'K':
            return 1 << 10;
        case 'm':
        case 'M':
            return 1 << 20;
        case 'g':
        case 'G':
            return 1 << 30;
    }
    return 0;
}

static void usage(char* prog) {
    printf("usage: %s size{K,M,G} [repeat]\n", prog);
}

int is_afs_env = 0;
typedef enum { WRITE, READ } io_op_t;

inline clock_t file_io(io_op_t op, char* fname, int64_t total_size) {
    FILE* fd;
    char c = '1';
    clock_t diff = clock();
    size_t temp;

    fd = fopen(fname, (op == WRITE ? "wb+" : "rb"));
    if (fd == NULL) {
        printf("error: could not open file '%s'\n", fname);
        exit(-1);
    }

    for (int64_t j = 0; j < total_size; j++) {
        if (op == WRITE) {
            temp = fwrite(&c, sizeof(uint8_t), 1, fd);
        } else {
            temp = fread(&c, sizeof(uint8_t), 1, fd);
        }

        if (temp != sizeof(uint8_t)) {
            printf("I/O error, %s returned %zu\n",
                   (op == WRITE ? "fwrite" : "fread"), temp);
            exit(-1);
        }
    }

    fsync(fileno(fd));
    fclose(fd);
    return clock() - diff;
}

const char * flush_afs_cmd = "fs flush -p ./%s";

static void gen_file(int64_t total_size, int repeat) {
    int status;
    char fname[20], cmd[100];
    clock_t diff, total_write = 0, total_read = 0;
    double avg_read, avg_write;

    snprintf(fname, sizeof(fname), "file.%d", (int)getpid());
    if (is_afs_env) {
        snprintf(cmd, sizeof(cmd), flush_afs_cmd, fname);
    }

    for (int i = 0; i < repeat; i++) {
        total_write += file_io(WRITE, fname, total_size);
        /* here lets flush the file out of the cache */
        if (is_afs_env) {
            if ((status = system(cmd))) {
                printf("'%s' FAILED...\n", cmd);
            }
        }

        total_read += file_io(READ, fname, total_size);
        remove(fname);
    }

    avg_read = (((double)total_read) / repeat) / CLOCKS_PER_SEC;
    avg_write = (((double)total_write) / repeat) / CLOCKS_PER_SEC;

    printf("avg_read(s) = %lf \t avg_write(s) = %lf\n", avg_read, avg_write);
}

int main(int argc, char** argv) {
    int multiplier = 1, file_size = 0, stop_bool = 0, repeat = 1;
    int64_t total_size;
    char *p_c, *p_g, c;
    char buffer[1024], *str;

    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    for (p_c = argv[1]; (c = *p_c) != '\0'; p_c++) {
        if ((multiplier = get_mult(c))) {
            p_g = p_c + 1;
            break;
        }

        if (c >= '0' && c <= '9') {
            file_size = file_size * 10 + (c - '0');
        }
    }

    if (file_size <= 0) {
        usage(argv[0]);
        return -1;
    }

    if (argc > 2 && (repeat = atoi(argv[2])) == 0) {
        printf("error: repeat value '%s' is invalid\n", argv[2]);
        usage(argv[0]);
        return -1;
    }

    // now if we are in AFS
    str = getcwd(buffer, sizeof(buffer));
    if (strstr(str, "/afs") == str) {
        printf("Detected AFS env\n");
        is_afs_env = 1;
    }

    *p_g = '\0';
    total_size = multiplier * file_size;
    printf("Running test: size = %ld bytes (%s), repeat = %d\n", total_size,
           argv[1], repeat);

    gen_file(total_size, repeat);

    return 0;
}
