#include "nexus_tests.h"

struct supernode * gbl_supernode    = NULL;
struct volumekey * gbl_volumekey    = NULL;
struct dirnode *   gbl_root_dirnode = NULL;

void
setUp()
{
    int ret = -1;

    ret = nexus_init_enclave(TEST_ENCLAVE_PATH);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_init_enclave() FAILED");

    ret = nexus_create_volume(
        TEST_PUBLIC_KEY, &gbl_supernode, &gbl_root_dirnode, &gbl_volumekey);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_create_volume() FAILED");

    ret = nexus_login_volume(
        TEST_PUBLIC_KEY, TEST_PRIVATE_KEY, gbl_supernode, gbl_volumekey);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_login_volume() FAILED");
}

void
tearDown()
{
    nexus_free(gbl_supernode);
    nexus_free(gbl_volumekey);
    nexus_free(gbl_root_dirnode);
    sgx_destroy_enclave(global_enclave_id);
}

void
test_dirnode_new()
{
    int            ret = -1;
    struct uuid    uuid;
    struct dirnode dirnode = { 0 };

    ecall_dirnode_new(global_enclave_id,
                      &ret,
                      &uuid,
                      &gbl_root_dirnode->header.root_uuid,
                      &dirnode);
    TEST_ASSERT_MESSAGE(ret == 0, "ecall_dirnode_new FAILED");

    TEST_ASSERT_MESSAGE(sizeof(struct dirnode) == dirnode.header.total_size,
                        "the size of the dirnode != sizeof(struct dirnode)");
}

void
test_dirnode_basic1()
{
    int                 ret         = -1;
    nexus_fs_obj_type_t type        = NEXUS_ANY;
    char *              fname_test1 = "test.txt";
    char *              fname_test2 = NULL;
    struct dirnode *    sealed_dirnode = NULL;
    struct uuid         uuid1;
    struct uuid         uuid2;

    nexus_uuid(&uuid1);

    // -- Let's add a file into the dirnode
    ecall_dirnode_add(
        global_enclave_id, &ret, gbl_root_dirnode, &uuid1, fname_test1, NEXUS_FILE);

    TEST_ASSERT_MESSAGE(ret == 0, "ecall_dirnode_add FAILED");


    // -- Serialize the dirnode
    ecall_dirnode_serialize(
        global_enclave_id, &ret, gbl_root_dirnode, &sealed_dirnode);


    // -- Let's search for the uuid
    ecall_dirnode_find_by_uuid(global_enclave_id, &ret, gbl_root_dirnode, &uuid1,
            &fname_test2, &type);

    TEST_ASSERT_MESSAGE(ret == 0, "ecall_find_by_uuid FAILED");
    TEST_ASSERT_EQUAL_STRING(fname_test1, fname_test2);


    // -- remove the entry
    ecall_dirnode_remove(
        global_enclave_id, &ret, gbl_root_dirnode, fname_test1, &uuid1, &type);
    TEST_ASSERT_MESSAGE(ret == 0, "ecall_dirnode_remove FAILED");


    // -- let's make sure we can the new version
    nexus_free2(fname_test2);
    ecall_dirnode_find_by_uuid(global_enclave_id, &ret, gbl_root_dirnode, &uuid1,
            &fname_test2, &type);


    TEST_ASSERT_MESSAGE(ret != 0, "ecall_find_by_uuid FAILED");
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_dirnode_new);
    RUN_TEST(test_dirnode_basic1);
    return UNITY_END();
}
