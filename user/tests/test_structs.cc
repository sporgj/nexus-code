#include "ucafs_tests.h"

const char * dnode_file = "./repo/dnode-test";

#define N 6
TEST(DIRNODE, test1)
{
    ucafs_entry_type atype;
    uc_dirnode_t * dirnode = dirnode_new();
    shadow_t * shadows[N];
    sds fname, dnode_fname = sdsnew(dnode_file);
    const char * name;

    /* initialize the enclave */
    if (ucafs_init_enclave()) {
        return;
    }

    for (size_t x = 0; x < N; x++) {
        fname = string_and_number("test", x);

        shadows[x] = dirnode_add(dirnode, fname, UC_FILE, 0);

        sdsfree(fname);
    }

    ASSERT_TRUE(dirnode_write(dirnode, dnode_file));
    dirnode_free(dirnode);

    ASSERT_FALSE((dirnode = dirnode_from_file(dnode_fname)) == NULL) << "oops";

    for (size_t x = 0; x < N; x++) {
        name = dirnode_enc2raw(dirnode, shadows[x], UC_FILE, &atype);
        ASSERT_TRUE(name != NULL);
    }

    dirnode_free(dirnode);
    sdsfree(dnode_fname);
}

#if 0
TEST(DIRNODE, test1)
{
    uc_dirnode_t * dirnode = dirnode_new();
    shadow_t *shdw1 = NULL, *shdw2;
    const char *fname = "test", *str1;
    char * temp1;
    ucafs_entry_type atype;

    /* 1 - adding entry to the dirnode */
    uinfo("adding %s to dirnode", fname);
    shdw1 = dirnode_add(dirnode, fname, UC_FILE);
    ASSERT_FALSE(shdw1 == NULL) << "dirnode_add returned NULL";

    log_info("dirnode_add: fname -> %s", (temp1 = filename_bin2str(shdw1)));

    /* 2 - converting shadow to real */
    uinfo("dirnode_enc2raw");
    str1 = dirnode_enc2raw(dirnode, shdw1, atype, &atype);
    ASSERT_FALSE(str1 == NULL) << "dirnode_enc2raw returned NULL";

    ASSERT_STREQ(fname, str1) << "oops";

    /* 3 - raw to shadow */
    uinfo("dirnode_raw2enc");
    shdw2 = (shadow_t *)dirnode_raw2enc(dirnode, fname, atype, &atype);
    ASSERT_EQ(0, memcmp(shdw1, shdw2, sizeof(shadow_t)));

    uinfo("dirnode_rm");
    shdw2 = (shadow_t *)dirnode_rm(dirnode, fname, atype, &atype, NULL);
    ASSERT_EQ(0, memcmp(shdw1, shdw2, sizeof(shadow_t)));

    dirnode_free(dirnode);

    free(shdw1);
    free(shdw2);
    free(temp1);
}

TEST(DIRNODE, test2)
{
    uc_dirnode_t *dirnode = dirnode_new(), *dirnode2;
    shadow_t *shdw1 = NULL, *shdw2;
    const char *tpl = "file%d.txt", *fname = "dirnode.txt";
    char buffer[30];

    ASSERT_EQ(0, ucafs_init_enclave()) << "Enclave failed: "
                                       << ENCLAVE_FILENAME;

    for (size_t i = 1; i < 6; i++) {
        snprintf(buffer, sizeof(buffer), tpl, i);

        shdw1 = dirnode_add(dirnode, buffer, UC_FILE);
        ASSERT_FALSE(shdw1 == NULL) << "dirnode_add (" << buffer << ") FAILED";

        free(shdw1);
    }

    ASSERT_TRUE(dirnode_write(dirnode, fname));

    dirnode2 = dirnode_from_file(sdsnew(fname));
    ASSERT_FALSE(dirnode2 == NULL) << "dirnode_from_file returned NULL";

    dirnode_free(dirnode);
}

TEST(DIRNODE, test3)
{
    uc_dirnode_t *dirnode1 = dirnode_new(), *dirnode2;
    shadow_t * shdw1 = NULL;
    const shadow_t * shdw2 = NULL;
    ucafs_entry_type atype;
    const char *link_fname = "link.txt", *fname = "dummy_dirnode",
               *target_path = "./dell.txt";
    int len, link_info_len;
    link_info_t * link_info = NULL;
    const link_info_t * link_info1;

    len = strlen(target_path);
    link_info_len = len + sizeof(link_info_t) + 1;
    link_info = (link_info_t *)calloc(1, link_info_len);

    ASSERT_FALSE(link_info == NULL) << "allocation failed";

    link_info->total_len = link_info_len;
    link_info->type = UC_SOFTLINK;
    /* the meta file is useless */
    memcpy(&link_info->target_link, target_path, len);

    /* 5 - add it to the dirnode */
    shdw1 = dirnode_add_link(dirnode1, link_fname, link_info);
    ASSERT_FALSE(shdw1 == NULL) << "dirnode_add_link FAILED :(";

    shdw2 = dirnode_traverse(dirnode1, link_fname, UC_LINK, &atype, &link_info1);
    ASSERT_FALSE(shdw2 == NULL);

    ASSERT_TRUE(dirnode_write(dirnode1, fname));

    dirnode_free(dirnode1);
}
#endif
