/**
 *
 * UCAFS userland daemon process
 * @author judicael
 *
 */
#include <glog/logging.h>
#include <iostream>
#include <fstream>

#include <sys/stat.h>
#include <unistd.h>
#include <sgx_urts.h>

#include "dirnode.h"
#include "uspace.h"
#include "enclave_common.h"

#define ENCLAVE_FILENAME "sgx/enclave.so"

using namespace std;

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_rx(int);

const char afs_path[] = "/afs/maatta.sgx/user/bruyne";
static bool check_main_dir()
{
    string * afsx_repo = uspace_get_repo_path();
    fstream f1(afsx_repo->c_str(), ios::in);
    struct stat stat_buf;

    if (!f1) {
        // create the folder
        if (mkdir(afsx_repo->c_str(), S_IRWXG)) {
            LOG(ERROR) << "Could not mkdir: " << afsx_repo;
            return false;
        }
    }
    f1.close();
    delete afsx_repo;

    string * afsx_dnode = uspace_get_dnode_fpath();
    if (stat(afsx_dnode->c_str(), &stat_buf)) {
        cout << ". Initializing a new filebox" << endl;
        fstream f2(afsx_dnode->c_str(), ios::out | ios::binary);
        DirNode * dirnode = new DirNode;
        if (!DirNode::write(dirnode, &f2)) {
            cout << ". Writing main dirnode failed" << endl;
            return false;
        }
        f2.close();
    }

    delete afsx_dnode;

    cout << ". Everything looks ok" << endl;
    return true;
}

int main(int argc, char ** argv)
{
    int ret, updated;
    uspace_set_afs_home(afs_path, true);

    /* initialize the enclave */
    sgx_launch_token_t token;
    sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        cout <<  "Could not open enclave" << endl;
        return -1;
    }

    cout << ". Loaded enclave" << endl;

    google::InitGoogleLogging("--logtostderr=1");
    if (!check_main_dir()) {
        return -1;
    }
    setup_rx(0);

    return 0;
}
