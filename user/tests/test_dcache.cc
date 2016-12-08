/** test the dcache innerworkings
 * @param Judicael Briand */

const char * test_dirs[]
    = { "foo", "foo/bar", "foo/bar/gun", "win", "win/dows" };

const char * test_files[]
    = { "foo/bar/hello.txt", "foo/briand.txt", "win/dows/file.txt" };

#include <sys/stat.h>
#include <unistd.h>

#include "uc_test.h"

TEST(TestDCache, SimpleTest1)
{
    char * temp;
    sds path;
    for (size_t i = 0; i < sizeof(test_dirs) / sizeof(char *); i++) {
        path = MK_PATH(test_dirs[i]);
        ASSERT_EQ(0, dirops_new(path, UC_DIR, &temp)) << "DIR: " << path
                                                      << " FAILED";
        sdsfree(path);
        free(temp);
    }

    for (size_t i = 0; i < sizeof(test_files) / sizeof(char *); i++) {
        path = MK_PATH(test_dirs[1]);
        ASSERT_EQ(0, dirops_new(path, UC_FILE, &temp)) << "FILE: " << path
                                                       << " FAILED";
        sdsfree(path);
        free(temp);
    }
}

int
main(int argc, char ** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int status;
    char cmd[100] = { 0 };
    setup_repo_path();
    sds dir = uc_get_repo_path();

    // destroy all files in the repo folder
    sprintf(cmd, "rm -rf %s", dir);
    // cout << "Running: " << cmd;
    status = system(cmd);
    // cout << ", status = " << status << endl;

    sprintf(cmd, "mkdir -p %s", dir);
    // cout << "Running: " << cmd;
    status = system(cmd);
    // cout << ", status = " << status << endl;

    create_default_dnode();
    init_systems();
    sdsfree(dir);

    return RUN_ALL_TESTS();
}
