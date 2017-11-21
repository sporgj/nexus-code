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

    ret = write_volume_metadata_files(gbl_supernode,
                                      gbl_root_dirnode,
                                      gbl_volumekey,
                                      TEST_METADATA_PATH,
                                      TEST_VOLUMEKEY_PATH);
    TEST_ASSERT_MESSAGE(ret == 0, "write_volume_metadata_files() FAILED");

    ret = nexus_vfs_init();
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_vfs_init() FAILED");

    ret = nexus_mount_volume(
        gbl_supernode, gbl_volumekey, TEST_METADATA_PATH, TEST_DATADIR_PATH);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_mount_volume() FAILED");
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
test_dirops_basic1()
{
    int         ret         = -1;
    char *      fname_test1 = "test.txt";
    char *      fname_test2 = NULL;
    char *      nexus_name1 = NULL;
    char *      nexus_name2 = NULL;
    char *      nexus_name3 = NULL;
    struct uuid uuid1;
    struct uuid uuid2;

    nexus_uuid(&uuid1);

    ret = nexus_new(TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name1);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_new() FAILED");

    ret = nexus_lookup(
        TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name2);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_lookup() FAILED");

    // check that the string messages match
    TEST_ASSERT_EQUAL_STRING_MESSAGE(nexus_name1, nexus_name2, "lookup failed");

    ret = nexus_filldir(
        TEST_DATADIR_PATH, nexus_name1, NEXUS_FILE, &fname_test2);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_filldir() FAILED");

    ret = nexus_remove(
        TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name3);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_lookup() FAILED");

    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        nexus_name1, nexus_name3, "remove returned the wrong file name");

    nexus_free(nexus_name2);
    ret = nexus_lookup(
        TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name2);
    TEST_ASSERT_MESSAGE(ret != 0, "nexus_lookup returned file illegally");

    nexus_free(nexus_name1);
    nexus_free(nexus_name2);
    nexus_free(nexus_name3);
    nexus_free(fname_test2);
}

int
main()
{
    UNITY_BEGIN();
    RUN_TEST(test_dirops_basic1);

    return UNITY_END();
}
