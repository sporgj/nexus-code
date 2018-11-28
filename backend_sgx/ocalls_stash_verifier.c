#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nexus_hashtable.h>
#include <nexus_util.h>
#include <enclave/stash_verifier.h>

//
//void 
//stash_verifier_update


//void 
//stash_verifier_flush

static struct nexus_hashtable * stash_verifier_htable = NULL;

int
stash_verifier_init()
{
    stash_verifier_htable = nexus_create_htable(17, __uuid_hasher, __uuid_equals);

    return 0;
}

int
stash_verifier_exit()
{
    nexus_free_htable(stash_verifier_htable, 1, 0);
    return 0;
}

void
stash_verifier_evict(struct nexus_uuid * uuid)
{
    struct metadata_info * info = NULL;

    info = (struct stash_verifier_htable *)nexus_htable_remove(stash_verifier_htable, (uintptr_t)uuid, 0);

    nexus_free(info);
}


void
ocall_print2(char * str)
{
 
    void * ptr = NULL;

    ptr = calloc(12 , sizeof(char));
    
    strcpy((char*)ptr, "testingonly");
    
    printf("%s", (char*)ptr);
    fflush(stdout);
}