#include "nexus_tests.h"

void
setUp()
{
    int ret = -1;

    ret = nexus_init();
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_init_enclave() FAILED");

    ret = nexus_create_volume(
        TEST_METADATA_PATH, TEST_PUBLIC_KEY, TEST_VOLUMEKEY_PATH);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_create_volume() FAILED");

    ret = nexus_mount_volume(
        TEST_METADATA_PATH, TEST_DATADIR_PATH, TEST_VOLUMEKEY_PATH,
        TEST_PUBLIC_KEY, TEST_PRIVATE_KEY);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_mount_volume() FAILED");
}

void
tearDown()
{
    nexus_exit();
}

void
test_dirops_basic1()
{
    char * fname_test1 = "test1.txt";
    char * fname_test2 = "test2.txt";

    char * temp_fname1 = NULL;

    char * nexus_name1 = NULL;
    char * nexus_name2 = NULL;
    char * nexus_name3 = NULL;

    struct uuid uuid1;
    struct uuid uuid2;

    int ret = -1;

    nexus_uuid(&uuid1);

    // insert two files
    ret = nexus_new(TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name1);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_new() FAILED");

    ret = nexus_new(TEST_DATADIR_PATH, fname_test2, NEXUS_FILE, &nexus_name2);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_lookup() FAILED");
    nexus_free(nexus_name2);

    // lookup the first
    ret = nexus_lookup(
        TEST_DATADIR_PATH, fname_test1, NEXUS_FILE, &nexus_name2);
    
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_lookup() FAILED");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(nexus_name1, nexus_name2, "lookup failed");

    // try to filldir
    ret = nexus_filldir(
        TEST_DATADIR_PATH, nexus_name1, NEXUS_FILE, &temp_fname1);
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
    nexus_free(nexus_name3);
}

void
test_dirops_basic2()
{
    char * foodir      = "foo";
    char * dirpath_foo = filepath_from_name(strdup(TEST_DATADIR_PATH), foodir);

    char * test_fname1 = "test1.txt";
    char * test_fname2 = "test2.txt";

    char * temp_fname1 = NULL;

    char * nexus_name1 = NULL;
    char * nexus_name2 = NULL;
    char * nexus_name3 = NULL;

    struct uuid uuid1;

    int ret = -1;

    nexus_uuid(&uuid1);

    ret = nexus_new(TEST_DATADIR_PATH, foodir, NEXUS_DIR, &nexus_name1);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_new FAILED");

    ret = nexus_new(dirpath_foo, test_fname1, NEXUS_FILE, &nexus_name2);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_new FAILED");

    ret = nexus_new(dirpath_foo, test_fname2, NEXUS_FILE, &nexus_name3);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_new FAILED");

    ret = nexus_lookup(dirpath_foo, test_fname1, NEXUS_FILE, &temp_fname1);
    TEST_ASSERT_MESSAGE(ret == 0, "nexus_lookup FAILED");

    TEST_ASSERT_EQUAL_STRING_MESSAGE(nexus_name2, temp_fname1, "lookup failed");
}

int
main()
{
    UNITY_BEGIN();
    RUN_TEST(test_dirops_basic1);
    RUN_TEST(test_dirops_basic2);

    return UNITY_END();
}
