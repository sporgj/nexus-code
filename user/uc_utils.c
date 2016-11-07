#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "uc_utils.h"

// https://gist.github.com/ccbrown/9722406
void
hexdump(uint8_t * data, uint32_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' '
            && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

#define MAXPATHLEN 1024
char *
do_absolute_path(const char * path)
{
    char *p, *fres;
    const char * q;
    char * resolved;
    int first = 1;

    fres = resolved = malloc(MAXPATHLEN);
    if (resolved == NULL)
        return NULL;

    p = resolved;
loop:
    /* Skip any slash. */
    while (*path == '/')
        path++;

    if (*path == '\0') {
        if (p == resolved)
            *p++ = '/';
        *p = '\0';
        return resolved;
    }

    /* Find the end of this component. */
    q = path;
    do
        q++;
    while (*q != '/' && *q != '\0');

    /* Test . or .. */
    if (path[0] == '.') {
        if (q - path == 1) {
            path = q;
            goto loop;
        }
        if (path[1] == '.' && q - path == 2) {
            /* Trim the last component. */
            if (p != resolved)
                while (*--p != '/' && p != resolved)
                    continue;
            path = q;
            goto loop;
        }
    }

    /* Append this component. */
    if (p - resolved + 1 + q - path + 1 > MAXPATHLEN) {
        errno = ENAMETOOLONG;
        if (p == resolved)
            *p++ = '/';
        *p = '\0';
        goto out;
    }

    if (first) {
        memcpy(&p[0], path, q - path);
        first = 0;
        p[q - path] = '\0';

        p += q - path;
    } else {
        p[0] = '/';
        memcpy(&p[1], path, q - path);
        p[1 + q - path] = '\0';

        p += 1 + q - path;
    }

    path = q;
    goto loop;
out:
    free(fres);
    return NULL;
}

sds
do_make_path(const char * dirpath, const char * fname)
{
    sds result = sdsnew(dirpath);
    result = sdscat(result, "/");
    result = sdscat(result, fname);

    return result;
}

sds
do_get_fname(const char * fpath)
{
    const char * result = fpath + strlen(fpath);
    while (*result != '/' && result != fpath) {
        result--;
    }

    if (result == fpath) {
        return sdsnew(result);
    }

    return sdsnew(result + 1);
}

sds
do_get_dir(const char * fpath)
{
    const char * result = fpath + strlen(fpath);
    while (*result != '/' && result != fpath) {
        result--;
    }

    if (result == fpath) {
        return sdsnew(fpath);
    }

    return sdsnewlen(fpath, (uintptr_t)(result - fpath));
}
