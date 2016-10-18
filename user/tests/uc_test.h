#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <iostream>

#include <third/sds.h>

#include <cdefs.h>
#include <uc_dirnode.h>
#include <uc_dcache.h>
#include <uc_dirops.h>
#include <uc_sgx.h>
#include <uc_uspace.h>

using namespace std;

#ifdef __cplusplus
}
#endif

#define TEST_REPO_DIR "repo"
#define ENCLAVE_FILENAME "../sgx/enclave.signed.so"

sgx_enclave_id_t global_eid = 0;

extern "C" void dcache_init();

static sds MK_PATH(const char * path)
{
    sds rv = sdsnew(TEST_REPO_DIR);
    rv = sdscat(rv, "/");
    rv = sdscat(rv, path);

    return rv;
}

static void
create_default_dnode()
{
    sds path = uc_main_dnode_fpath();
    uinfo("Creating: %s", path);
    uc_dirnode_t * dnode = dirnode_new();
    if (!dirnode_write(dnode, path)) {
        uerror("Could not write: %s", path);
    }

    sdsfree(path);
    dirnode_free(dnode);
}

static int
init_enclave()
{
    int ret, updated;
    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        cout << "Could not open enclave: ret=" << ret << endl;
        return -1;
    }

    ecall_init_enclave(global_eid, &ret);
    if (ret) {
        cout << "Enclave could not be initialized" << endl;
        return -1;
    }

    cout << "Loaded enclave" << endl;

    return 0;
}

static void
init_systems()
{
    uinfo("Initializing...");
    uc_set_afs_home(TEST_REPO_DIR, NULL, false);
    dcache_init();
    if (init_enclave()) {
        exit(-1);
    }
}
