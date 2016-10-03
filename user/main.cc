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
#include <sgx_urts.h>

#include "uc_dnode.h"
#include "uc_uspace.h"
#include "enclave_common.h"

#define ENCLAVE_FILENAME "sgx/enclave.signed.so"

using namespace std;

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_rx(int);

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
        struct dirnode * dirnode = dn_new();
        if (!dn_write(dirnode, afsx_dnode)) {
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

    cout << ". Loaded enclave" << endl;

    if (!check_main_dir()) {
        return -1;
    }
    setup_rx(0);

    return 0;
}
