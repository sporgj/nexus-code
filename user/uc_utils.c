#include <stdio.h>
#include <string.h>

#include "third/sds.h"

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

sds
do_get_fname(const char * fpath)
{
    const char * result = fpath + strlen(fpath);
    while (*result != '/' && result != fpath) {
        result--;
    }

    if (result == fpath) {
        return NULL;
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
        return NULL;
    }

    return sdsnewlen(fpath, (uintptr_t)(result - fpath));
}
