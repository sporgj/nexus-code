#include "ucafs_tests.h"

TEST(DIROPS, test1)
{
    ASSERT_EQ(0, start_testbed()) << "Starting testbed failed";
    sds root_path = do_make_path(global_supernode_paths[0], UCAFS_WATCH_DIR);
    
    const char * fname = "foo";
    sds filepath = do_make_path(root_path, fname);
    char * temp;

    ASSERT_EQ(0, dirops_new(filepath, UC_DIR, &temp));

    free(temp);
    sdsfree(filepath);
    sdsfree(root_path);
}
