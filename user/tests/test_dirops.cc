/**
 * Tests the directory operations
 * @author Judicael Briand
 */

#include <sys/stat.h>
#include <unistd.h>

#include <gperftools/heap-profiler.h>

#include "uc_test.h"

#define TOTAL_FILE_COUNT 600

class TestDirops : public ::testing::Test {
protected:
    virtual void SetUp()
    {
	int status;
	char cmd[100] = {0};
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
    }
};

TEST_F(TestDirops, FileCreation) {
    const char * fname = "test.txt";
    char *test, *test2;
    sds path = MK_PATH(fname);

    /* checking dirops_new returns 0 */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test))
	<< "dirops_new failed";

    /* Asserting the filebox file was creating */
    struct stat stat_buf;
    sds path2 = uc_get_dnode_path(file_to_meta(test));
    ASSERT_EQ(0, stat(path2, &stat_buf))
	<< "Filebox " << path2 << " does not exist";

    /* deleting the entry from the dirnode */
    ASSERT_TRUE(dirops_remove(path, UC_FILE, &test2) == 0)
	<< path << " could not be removed";

    /* checking that the string from creating is same as deletion */
    ASSERT_STREQ(test, test2) << "Deleted string is different from created one";

    /* Verifying the filebox file has been deleted */
    ASSERT_NE(0, stat(path2, &stat_buf)) << "Filebox file '" << path2
                                         << "' was not deleted";

    free(test);
    free(test2);
    sdsfree(path);
    sdsfree(path2);
}

TEST_F(TestDirops, FileCreationMemTest) {
    const char *dname1 = "foo", *dname2 = "bar";
    char *temp1, *temp2;

    sds path1 = MK_PATH(dname1), path2 = do_make_path(path1, dname2);

    HeapProfilerStart("create");
    for (size_t i = 0; i < 1000; i++) {
	ASSERT_EQ(0, dirops_new(path1, UC_DIR, &temp1));
	free(temp1);

	ASSERT_EQ(0, dirops_new(path2, UC_DIR, &temp2));
	free(temp2);

	ASSERT_EQ(0, dirops_remove(path2, UC_DIR, &temp2));
	free(temp2);

	ASSERT_EQ(0, dirops_remove(path1, UC_DIR, &temp2));
	free(temp2);
    }
    HeapProfilerDump("done now");
    HeapProfilerStop();
}

TEST_F(TestDirops, FileRenaming1) {
    const char * fname1 = "test1.txt", * fname2 = "test2.txt";
    sds path1 = MK_PATH(fname1), path2 = MK_PATH(fname2), temp_path = NULL;
    char * temp1, * temp2, * temp3, * temp4;
    ucafs_entry_type type = UC_FILE;
    struct stat stat_buf;
    
    /* Creating the files */
    ASSERT_EQ(0, dirops_new(path1, type, &temp1))
	<< "dirops_new failed";

    uinfo("Renaming: %s -> %s", path1, path2);
    ASSERT_EQ(0, dirops_move1(path1, path2, type, &temp2, &temp3))
	<< "dirops_move1 failed";

    /* verifying the names are not the same */
    ASSERT_STREQ(temp1, temp2) << "renaming sent the wrong old name"; 

    ASSERT_STRNE(temp1, temp3) << "new and old name should differ";

    /* check that the renamed file is not accessible */
    temp_path = do_get_dir(path1);
    ASSERT_NE(0, dirops_code2plain(temp1, temp_path, type, &temp4));
    sdsfree(temp_path);

    /* verifying the old dnode path is not accessible */
    temp_path = uc_get_dnode_path(file_to_meta(temp1));
    ASSERT_NE(0, stat(temp_path, &stat_buf)) << temp_path
                                             << " should not exist";
    sdsfree(temp_path);

    temp_path = uc_get_dnode_path(file_to_meta(temp3));
    ASSERT_EQ(0, stat(temp_path, &stat_buf)) << temp_path
	<< " filebox is not accessible";
    sdsfree(temp_path);

    free(temp1);
    free(temp2);
    free(temp3);
    sdsfree(path1);
    sdsfree(path2);
}

TEST_F(TestDirops, HardLinkTest1)
{
    create_default_dnode();
    const char * filename = "test.txt", * linkname = "test2.txt";
    char * temp, * temp2, *temp3;
    sds filepath = MK_PATH(filename), linkpath = MK_PATH(linkname),
        filebox_path;
    sds filedir = do_get_dir(filepath), linkdir = do_get_dir(linkpath);
    struct stat stat_buf;

    /* 1 - Create the file */
    ASSERT_EQ(0, dirops_new(filepath, UC_FILE, &temp))
	<< "dirops_new failed";
    filebox_path = uc_get_dnode_path(file_to_meta(temp));

    /* 2 - hardlink the file */
    ASSERT_EQ(0, dirops_hardlink(filepath, linkpath, &temp2));

    /* 3 - delete original file */
    ASSERT_TRUE(dirops_remove(filepath, UC_FILE, &temp) == 0)
	<< filepath << " could not be removed";

    /* 4 - Access the hardlink */
    ASSERT_EQ(0, dirops_plain2code(linkpath, UC_FILE, &temp3))
	<< "Could not reference hardlink";
    ASSERT_EQ(0, dirops_code2plain(temp3, linkdir, UC_FILE, &temp3));

    /* 5 - Check filebox file still exists */
    ASSERT_EQ(0, stat(filebox_path, &stat_buf))
	<< "Filebox should not be deleted";

    /* 6 - Delete hardlink */
    ASSERT_EQ(0, dirops_remove(linkpath, UC_FILE, &temp)); 

    /* 7 - Access the hardlink */
    ASSERT_NE(0, dirops_plain2code(linkpath, UC_FILE, &temp3))
	<< "Could not reference hardlink";
    ASSERT_NE(0, dirops_code2plain(temp3, linkdir, UC_FILE, &temp3));

    /* 5 - Check filebox file still exists */
    ASSERT_NE(0, stat(filebox_path, &stat_buf))
	<< "Filebox should not be deleted";
}

TEST_F(TestDirops, HardLinkTest2)
{
    create_default_dnode();
    const char * filename = "test.txt", * linkname = "test2.txt";
    char * temp, * temp2, *temp3;
    sds filepath = MK_PATH(filename), linkpath = MK_PATH(linkname),
        filebox_path;
    sds filedir = do_get_dir(filepath), linkdir = do_get_dir(linkpath);
    struct stat stat_buf;

    /* 1 - Create the file */
    ASSERT_EQ(0, dirops_new(filepath, UC_FILE, &temp))
	<< "dirops_new failed";
    filebox_path = uc_get_dnode_path(file_to_meta(temp));

    /* 2 - hardlink the file */
    ASSERT_EQ(0, dirops_hardlink(filepath, linkpath, &temp2));

    /* 3 - delete hardlink */
    ASSERT_TRUE(dirops_remove(linkpath, UC_FILE, &temp) == 0)
	<< filepath << " could not be removed";

    /* 4 - Access the file */
    ASSERT_EQ(0, dirops_plain2code(filepath, UC_FILE, &temp3))
	<< "Could not reference file";
    ASSERT_EQ(0, dirops_code2plain(temp3, filedir, UC_FILE, &temp3));

    /* 5 - Check filebox file still exists */
    ASSERT_EQ(0, stat(filebox_path, &stat_buf))
	<< "Filebox should not be deleted";

    /* 6 - Delete the file */
    ASSERT_EQ(0, dirops_remove(filepath, UC_FILE, &temp)); 

    /* 7 - Access the file */
    ASSERT_NE(0, dirops_plain2code(filepath, UC_FILE, &temp3))
	<< "Could not reference file";
    ASSERT_NE(0, dirops_code2plain(temp3, filedir, UC_FILE, &temp3));

    /* 5 - Check filebox file still exists */
    ASSERT_NE(0, stat(filebox_path, &stat_buf))
	<< "Filebox should not be deleted";
}

TEST_F(TestDirops, HardLinkTest3)
{
    const char * filename = "test.txt", * linkname = "test2.txt";
    char * temp, * temp2, *temp3;
    sds filepath = MK_PATH(filename), linkpath = MK_PATH(linkname);
    uc_filebox_t * filebox1, * filebox2;

    /* 1 - Create the file */
    ASSERT_EQ(0, dirops_new(filepath, UC_FILE, &temp))
	<< "dirops_new failed";

    /* 2 - hardlink the file */
    ASSERT_EQ(0, dirops_hardlink(filepath, linkpath, &temp2));

    /* 3 - Get the filebox of the original file */
    ASSERT_TRUE((filebox1 = dcache_get_filebox(filepath)) != NULL)
	<< "Getting the file's filebox failed";

    ASSERT_TRUE((filebox2 = dcache_get_filebox(linkpath)) != NULL)
	<< "Getting the link's filebox failed";

    ASSERT_EQ(1, filebox_equals(filebox1, filebox2))
	<< "fileboxes must equal one another";
}

TEST_F(TestDirops, SymLinkTest1)
{
    const char * fname = "test.txt", * lname = "test2.txt";
    sds filepath = MK_PATH(fname), linkpath = MK_PATH(lname);
    char * temp1, * temp2, * temp3;
    uc_filebox_t * fb1, * fb2;

    /* 1 - Create the file */
    ASSERT_EQ(0, dirops_new(filepath, UC_FILE, &temp1))
	<< "Creating new file failed";

    ASSERT_FALSE((fb1 = dcache_get_filebox(filepath)) == NULL)
	<< "Link filebox cannot be null";

    /* 2 - Symlink the file */
    ASSERT_EQ(0, dirops_symlink(linkpath, fname, &temp2))
	<< "Symlinking failed";

    /* 3 - Access the symlink */
    ASSERT_EQ(0, dirops_plain2code(linkpath, UC_LINK, &temp3))
	<< "Getting shadow name failed";

    ASSERT_STREQ(temp2, temp3) << "Dereferenced link incorrect";

    /* 4 - Dereference the symlink */
    ASSERT_FALSE((fb2 = dcache_get_filebox(linkpath)) == NULL)
	<< "Link filebox cannot be null";

    /* 5 - Make sure they're the same */
    ASSERT_TRUE(filebox_equals(fb1, fb2)) << "Filebox should be equal";

    /* 6 - Delete the original file */
    ASSERT_EQ(0, dirops_remove(filepath, UC_FILE, &temp1))
	<< "Removing file failed";

    /* 7 - Dereference the symlink, expect NULL */
    ASSERT_TRUE((fb2 = dcache_get_filebox(linkpath)) == NULL)
	<< "Link filebox should be null";
}

TEST_F(TestDirops, SymLinkTest2)
{
    uc_filebox_t * fb1, * fb2;
    const char *dir1 = "foo", *dir2 = "bar", *dir3 = "bad", *dir4 = "good",
               *fname = "test.txt";
    sds dir1_path = MK_PATH(dir1), dir2_path = MK_PATH(dir2),
        dir3_path = MK_PATH(dir3), dir4_path = MK_PATH(dir4);

    sds filepath = do_make_path(dir2_path, fname),
	linktget = do_make_path("..", dir2),
	linkpath = do_make_path(dir3_path, fname),
	link2tget = do_make_path(".", dir2),
	link2path = do_make_path(dir4_path, fname);


    char * temp1, * temp2, * temp3;

    /* 1 - Create the regular directories */
    ASSERT_EQ(0, dirops_new(dir1_path, UC_DIR, &temp1));
    ASSERT_EQ(0, dirops_new(dir2_path, UC_DIR, &temp2));
    ASSERT_EQ(0, dirops_new(filepath, UC_FILE, &temp3));

    /* 2 -Symlink the directory */
    ASSERT_EQ(0, dirops_symlink(dir3_path, linktget, &temp1))
	<< "Symlinking failed";

    /* 3 - Access the symlink */
    ASSERT_TRUE((fb1 = dcache_get_filebox(linkpath)) == NULL)
	<< "Dereferencing cannot lead to null";

    /* 4 - Access the file */
    ASSERT_FALSE((fb2 = dcache_get_filebox(filepath)) == NULL);

    ASSERT_EQ(0, dirops_symlink(dir4_path, link2tget, &temp3));

    ASSERT_FALSE((fb1 = dcache_get_filebox(link2path)) == NULL);

    /* 5 - Make sure they're the same */
    ASSERT_TRUE(filebox_equals(fb1, fb2));
}

#if 0
TEST(UC_DIROPS, SimpleFileCreation)
{
    const char * fname = "test.txt";
    char * test, * test2;
    sds path = MK_PATH(fname);

    /* checking dirops_new returns 0 */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test))
	<< "dirops_new failed";

    uinfo("%s -> %s", path, test); 
    uinfo("Looking filebox for '%s'", path);

    /* Asserting the filebox file was creating */
    struct stat stat_buf;
    sds path2 = uc_get_dnode_path(test);
    ASSERT_EQ(0, stat(path2, &stat_buf)) << "Filebox does not exist";

    /* deleting the entry from the dirnode */
    uinfo("Deleting %s", path);
    ASSERT_TRUE(dirops_remove(path, UC_FILE, &test2) == 0)
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
	ASSERT_EQ(0, dirops_new(buf, UC_FILE, &test));
	printf("\r%d/%d", i, TOTAL_FILE_COUNT);
	free(test);
    }
    printf("\n");

    uinfo("Looking up files...");
    /* generate a number of filenames */
    for (size_t i = 0; i < TOTAL_FILE_COUNT; i++) {
	snprintf(buf, sizeof(buf), "%s/img%d.png", TEST_REPO_DIR, i);
	ASSERT_EQ(0, dirops_plain2code(buf, UC_FILE, &test));
	printf("\r%d/%d", i, TOTAL_FILE_COUNT);
	free(test);
    }
    printf("\n");

    //HeapProfilerDump("Done here");
    //HeapProfilerStop();
}

// TODO free variables
TEST(UC_DIROPS, SillyRenameTest)
{
    create_default_dnode();
    const char * parent_path = "repo";
    const char * fname = "test.txt", * fname2 = "test2.txt";
    char * test, * test2;
    sds path = MK_PATH(fname), path2 = MK_PATH(fname2);

    /* checking dirops_new returns 0 */
    ASSERT_EQ(0, dirops_new(path, UC_FILE, &test))
	<< "dirops_new failed";
    uinfo("%s -> %s", path, test);

    /* do a sillyrename */
    ASSERT_EQ(0, dirops_rename2(parent_path, fname, fname2, UC_FILE, &test2)) <<
            "Could not sillyrename :(";

    ASSERT_NE(0, strcmp(test, test2)) << "Real and silly values have to differ";

    ASSERT_NE(0, dirops_plain2code(path, UC_FILE, &test))
        << "File is not suppose to be found";

    ASSERT_EQ(0, dirops_plain2code(path2, UC_FILE, &test))
        << "New file: " << path2 << " could not be found";

    ASSERT_EQ(0, strcmp(test, test2))
        << "dirops returns different lookup value: test1=" << test
        << ", test2=" << test2;

    sdsfree(path);
    sdsfree(path2);
}
#endif
