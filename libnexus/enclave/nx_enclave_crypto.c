#include "nx_trusted.h"

// TODO
int
supernode_encrypt_and_seal(struct supernode  * supernode,
                           struct volumekey * volkey)
{
    return 0;
}

int
supernode_decrypt_and_unseal(struct supernode *  supernode,
                             struct volumekey * volkey)
{
    return 0;
}

// TODO
int
dirnode_encrypt_and_seal(struct dirnode * dirnode, struct volumekey * volkey)
{
    return 0;
}

int
dirnode_decrypt_and_unseal(struct dirnode *    dirnode,
                           struct volumekey * volkey)
{
    return 0;
}

// TODO
int
volumekey_wrap(struct volumekey * volkey)
{
    return 0;
}

// TODO
int
volumekey_unwrap(struct volumekey * volkey)
{
    return 0;
}
