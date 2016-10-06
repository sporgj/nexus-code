/**
 *
 * UCAFS userland daemon process
 * @author judicael
 *
 */
#include <iostream>
#include <fstream>

#include <sys/stat.h>
#include <unistd.h>

#include "uc_dirnode.h"
#include "uc_dcache.h"
#include "uc_uspace.h"
#include "uc_sgx.h"

using namespace std;

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_rx(int);
extern "C" void dcache_init();

const char afs_path[] = "/afs/maatta.sgx/user/bruyne";
static bool check_main_dir()
{
    sds afsx_repo = uc_get_repo_path();
    struct stat stat_buf;

    if (stat(afsx_repo, &stat_buf)) {
        // create the folder
        if (mkdir(afsx_repo, S_IRWXG)) {
            cout << "Could not mkdir: " << afsx_repo << endl;
            return false;
        }
    }
    sdsfree(afsx_repo);

    sds afsx_dnode = uc_main_dnode_fpath();
    if (stat(afsx_dnode, &stat_buf)) {
        cout << ". Initializing a new filebox" << endl;
        struct dirnode * dirnode = dirnode_new();
        if (!dirnode_write(dirnode, afsx_dnode)) {
            cout << ". Writing main dirnode failed" << endl;
            return false;
        }
    }

    sdsfree(afsx_dnode);

    cout << ". Everything looks ok" << endl;
    return true;
}

int main(int argc, char ** argv)
{
    int ret, updated;
    uc_set_afs_home(afs_path, "sgx", true);

#if 0
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
#endif

    cout << ". Loaded enclave" << endl;

    dcache_init();

    if (!check_main_dir()) {
        return -1;
    }
    setup_rx(0);

    return 0;
}
