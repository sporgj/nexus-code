/**
 * Tests the directory operations
 * @author Judicael Briand
 */

#include <sys/stat.h>
#include <unistd.h>

#include <gperftools/heap-profiler.h>

#include "uc_test.h"

#define TOTAL_FILE_COUNT 600

TEST(UC_DIROPS, SimpleFileCreation)
{
    const char * fname = "test.txt";
    char * test, * test2;
    sds path = MK_PATH(fname);

    /* checking dirops_new returns 0 */
    ASSERT_EQ(0, dirops_new(path, UCAFS_TYPE_FILE, &test))
	<< "dirops_new failed";

    uinfo("%s -> %s", path, test); 
    uinfo("Looking filebox for '%s'", path);

    /* Asserting the filebox file was creating */
    struct stat stat_buf;
    sds path2 = uc_get_dnode_path(test);
    ASSERT_EQ(0, stat(path2, &stat_buf)) << "Filebox does not exist";

    /* deleting the entry from the dirnode */
    uinfo("Deleting %s", path);
    ASSERT_TRUE(dirops_remove(path, UCAFS_TYPE_FILE, &test2) == 0)
	<< path << " could not be removed";

    /* checking that the string from creating is same as deletion */
    ASSERT_STREQ(test, test2) << "Deleted string is different from created one";

    /* Verifying the filebox file has been deleted */
    ASSERT_FALSE(stat(path2, &stat_buf) == 0) << "Filebox file was not deleted";

    free(test);
    free(test2);
    sdsfree(path);
    sdsfree(path2);
}

TEST(UC_DIROPS, FileCreationMemTest)
{
    char buf[50], * test;

    //HeapProfilerStart("memtest");

    uinfo("Generating %d files...", TOTAL_FILE_COUNT);
    /* generate a number of filenames */
    for (size_t i = 0; i < TOTAL_FILE_COUNT; i++) {
	snprintf(buf, sizeof(buf), "%s/img%d.png", TEST_REPO_DIR, i);
	ASSERT_EQ(0, dirops_new(buf, UCAFS_TYPE_FILE, &test));
	printf("\r%d/%d", i, TOTAL_FILE_COUNT);
	free(test);
    }
    printf("\n");

    uinfo("Looking up files...");
    /* generate a number of filenames */
    for (size_t i = 0; i < TOTAL_FILE_COUNT; i++) {
	snprintf(buf, sizeof(buf), "%s/img%d.png", TEST_REPO_DIR, i);
	ASSERT_EQ(0, dirops_plain2code(buf, UCAFS_TYPE_FILE, &test));
	printf("\r%d/%d", i, TOTAL_FILE_COUNT);
	free(test);
    }
    printf("\n");

    //HeapProfilerDump("Done here");
    //HeapProfilerStop();
}

int main(int argc, char ** argv)
{
    init_systems();
    create_default_dnode();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
