#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define prefix_len 7

char *get_random_prefix() {
    char c, *buf;
    int j = 0;
    FILE *fd = fopen("/dev/urandom", "r");

    if (fd == NULL) {
        printf("Error: opening /dev/urandom failed\n");
        return NULL;
    }

    buf = calloc(1, prefix_len + 2);
    if (buf == NULL) {
        printf("Error: allocation failed\n");
        return NULL;
    }

    for (size_t i = 0; i < prefix_len;) {
        fread(&c, 1, 1, fd);

        if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) ||
            (c >= 97 && c <= 122)) {
            buf[j++] = c;
            i++;
        }
    }

    buf[prefix_len] = '_';

    fclose(fd);
    return buf;
}

char *get_format(size_t count) {
    const char *format = "%%s%%0%dd";
    int d = 0, len;
    while (count) {
        count /= 10;
        d++;
    }

    char *buf = malloc((len = d + sizeof(format)));
    if (buf == NULL) {
        return NULL;
    }

    snprintf(buf, len, format, d);
    return buf;
}

#define TIMING_BUFLEN 25
char *get_timing(size_t diff) {
    double elapsed = (1000.0 * diff) / CLOCKS_PER_SEC;
    char *rv = (char *)malloc(TIMING_BUFLEN);
    if (rv == NULL) {
        printf("! Allocation error on get_timing\n");
        return NULL;
    }

    snprintf(rv, TIMING_BUFLEN, "%.6f ms", elapsed);

    return rv;
}

void create_files(size_t count) {
    char *random_prefix = get_random_prefix();
    char name[prefix_len + 10];
    char *format = get_format(count);
    FILE *fp;
    int i, j;
    clock_t start = clock(), diff;

    for (i = 0; i < count; i++) {
        snprintf(name, sizeof(name), format, random_prefix, i);
        // now create file
        fp = fopen(name, "w");
        if (fp == NULL) {
            printf("! Error creating: %s\n", name);
            goto clear;
        }

        fclose(fp);
        fp = NULL;
    }

clear:
    diff = clock() - start;

    if (fp) {
        fclose(fp);
    }

    char *diff_str = get_timing(diff);
    printf(":: Created %d files (%s)\n", i, diff_str);
    free(diff_str);

    for (j = 0; j < i; j++) {
        snprintf(name, sizeof(name), format, random_prefix, j);

        if (unlink(name)) {
            break;
        }
    }

    printf(":: Deleted %d files\n", j);
}

int main(int argc, char **argv) {
    int x = 10;
    int num = 1;

    if (argc < 2) {
        printf("Please specify the number of files\n");
        return -1;
    }

    if ((num = atoi(argv[1])) <= 0) {
        printf("parsing '%s' failed\n", argv[1]);
        return -1;
    }

    printf(":: Workload: %d files\n", num);
    create_files(num);
    return 0;
}
