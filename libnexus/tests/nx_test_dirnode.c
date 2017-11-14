#include "nexus_tests.h"

CHEAT_DECLARE(struct supernode * supernode  = NULL;
              struct volumekey * volumekey  = NULL;
              struct dirnode * root_dirnode = NULL;)

CHEAT_SET_UP({
    int ret = -1;
    (void)fprintf(stdout, "Setting up");

    ret = nexus_init_enclave(TEST_ENCLAVE_PATH);
    cheat_assert(ret == 0);

    ret = nexus_create_volume(
        TEST_PUBLIC_KEY, &supernode, &root_dirnode, &volumekey);
    cheat_assert(ret == 0);

    ret = nexus_login_volume(
        TEST_PUBLIC_KEY, TEST_PRIVATE_KEY, supernode, volumekey);
    cheat_assert(ret == 0);
})

CHEAT_TEAR_DOWN({
    nexus_free(supernode);
    nexus_free(volumekey);
    nexus_free(root_dirnode);
})

CHEAT_TEST(creating_dirnode, {
    int            ret = -1;
    struct uuid    uuid;
    struct dirnode dirnode = {0};

    ecall_dirnode_new(global_enclave_id, &ret, &uuid, root_dirnode, &dirnode);
	cheat_assert(ret == 0);

	cheat_assert(sizeof(struct dirnode) == dirnode.header.total_size);
})
