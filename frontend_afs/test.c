#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afs.h"

#include "handler.h"




static const char * lookup_cmd =					\
    "op   : 4," "\n"							\
    "name : \"bla\"," "\n"						\
    "path : \"/afs/maatta.sgx/user/alice/test1\"," "\n"			\
    "type : 5" "\n";



int
main(int argc, char ** argv)
{
    uint8_t * resp = NULL;
    uint32_t resp_len = 0;

    
    dispatch_nexus_command((uint8_t *)lookup_cmd, strlen(lookup_cmd) + 1, &resp, &resp_len);


}
