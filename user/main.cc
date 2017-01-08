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

#define ENCLAVE_FILENAME "sgx/enclave.signed.so"

using namespace std;

FILE * global_mod_fid = NULL;

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_mod();
extern "C" void dcache_init();

const char afs_path[] = UCAFS_PATH;
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
        uc_dirnode_t * dirnode = dirnode_new_alias(&uc_root_dirnode_shadow_name);
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
    uc_set_afs_home(afs_path, UC_AFS_WATCH, true);

    /* initialize the enclave */
#ifdef UCAFS_SGX
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
#endif

    dcache_init();

    cout << ":: Checking " << afs_path << "..." << endl;
    if (!check_main_dir()) {
        return -1;
    }

    if (setup_mod()) {
        cout << " ! Could not access module" << endl;
        return -1;
    }

    cout << "Done..." << endl;

    while(1);

    return 0;
}
