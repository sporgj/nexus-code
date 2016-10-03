#include <string.h>
#include "sds.h"
#include "uc_utils.h"

// http://stackoverflow.com/questions/16804251/how-would-i-create-a-hex-dump-utility-in-c
void hexdump(uint8_t * buf, uint32_t len)
{
    
}

sds do_get_fname(const char * fpath)
{
    const char * result = fpath + strlen(fpath);
    while (*result != '/' && result != fpath) {
        result--;
    }

    return sdsnew(result + 1);
}
