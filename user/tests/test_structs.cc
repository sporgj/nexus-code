#include "ucafs_tests.h"

sgx_enclave_id_t global_eid = 0;

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

    free(shdw1);
    free(shdw2);
    free(temp1);
}
