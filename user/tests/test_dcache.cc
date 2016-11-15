/** test the dcache innerworkings
 * @param Judicael Briand */

const char * test_dirs[] = {
    "foo",
    "foo/bar",
    "win",
    "win/dows"
};

const char * test_files[] = {
    "foo/bar/hello.txt",
    "foo/briand.txt",
    "win/dows/file.txt"
};

#include "uc_test.h"

TEST(TestDCache, SimpleTest1) {
    char * temp;
    sds path;
    for (size_t i = 0; i < sizeof(test_dirs) / sizeof(char *); i++) {
        path = MK_PATH(test_dirs[1]);
        ASSERT_EQ(0, dirops_new(path, UC_DIR, &temp))
            << "DIR: " << path << " FAILED";
        sdsfree(path);
    }

    for (size_t i = 0; i < sizeof(test_files) / sizeof(char *); i++) {
        path = MK_PATH(test_dirs[1]);
        ASSERT_EQ(0, dirops_new(path, UC_FILE, &temp))
            << "FILE: " << path << " FAILED";
        sdsfree(path);
    }
}

int main(int argc, char ** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    setup_repo_path();
    init_systems();
    create_default_dnode();
    return RUN_ALL_TESTS();
}
