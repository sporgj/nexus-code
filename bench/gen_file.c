/**
 * Generates random file of random size
 * @author Judicael Djoko
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

static int get_mult(char c) {
    switch(c) {
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

static void usage(char * prog) {
    printf("usage: %s size{K,M,G} [repeat]\n", prog);
}

static void gen_file(int64_t total_size, int repeat)
{
    char fname[20], c = '1';
    FILE * fd;
    snprintf(fname, sizeof(fname), "file.%d", (int)getpid());
    clock_t diff, total_create = 0, total_delete = 0;
    double avg_create, avg_delete;

    for (int i = 0; i < repeat; i++) {
        fd = fopen(fname, "wb");
        if (fd == NULL) {
            printf("error: could not open file '%s'\n", fname);
            return;
        }

        diff = clock();
        for (int64_t j = 0; j < total_size; j++) {
            fwrite(&c, sizeof(uint8_t), 1, fd);
        }

        fsync(fileno(fd));
        fclose(fd);
        diff = clock() - diff;
        total_create += diff;

        diff = clock();
        remove(fname);
        diff = clock() - diff;
        total_delete += diff;
    }

    avg_create = (((double)total_create)/repeat)/CLOCKS_PER_SEC;
    avg_delete = (((double)total_delete)/repeat)/CLOCKS_PER_SEC;

    printf("avg_create = %lfs, avg_delete = %lfs\n", avg_create, avg_delete); 
}

int main(int argc, char ** argv)
{
    int multiplier = 1, file_size = 0, stop_bool = 0, repeat = 1;
    int64_t total_size;
    char * p_c, *p_g, c;

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

    *p_g = '\0';
    total_size = multiplier * file_size;
    printf("Running test: size = %ld bytes (%s), repeat = %d\n", total_size, argv[1], repeat);

    gen_file(total_size, repeat);

    return 0;
}
