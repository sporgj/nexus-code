#include "ucafs_tests.h"

sgx_enclave_id_t global_eid;

TEST(DIRNODE, test1) {
    uc_dirnode_t * dirnode = dirnode_new();
    shadow_t * shdw1 = NULL, * shdw2;
    const char * fname = "test", * str1;
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

TEST(DIRNODE, test2) {
    uc_dirnode_t * dirnode = dirnode_new(), * dirnode2;
    shadow_t * shdw1 = NULL, * shdw2;
    const char * tpl = "file%d.txt", *fname = "dirnode.txt";
    char buffer[30];

    ASSERT_EQ(0, ucafs_init_enclave()) << "Enclave failed: " << ENCLAVE_FILENAME;

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
