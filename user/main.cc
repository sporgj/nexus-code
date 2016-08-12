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

#include "common.h"
#include "uspace.h"
#include "dirnode.h"

using namespace std;

extern "C" int setup_rx();

const char * gbl_temp_dnode_path = UCAFS_TEMP_DNODE_STR;

const char afs_path[] = "/afs/maatta.sgx/user/bruyne";
static bool check_main_dir()
{
    string afsx_repo(UCAFS_TEMP_REPO);
    fstream f1(afsx_repo, ios::in);
    struct stat stat_buf;

    if (!f1) {
        // create the folder
        if (mkdir(afsx_repo.c_str(), S_IRWXG)) {
            LOG(ERROR) << "Could not mkdir: " << afsx_repo;
            return false;
        }
    }
    f1.close();

    string afsx_dnode(UCAFS_TEMP_DNODE_STR);

    if (stat(afsx_dnode.c_str(), &stat_buf)) {
        cout << ". Initializing a new filebox" << endl;
        fstream f2(afsx_dnode, ios::out | ios::binary);
        DirNode * dirnode = new DirNode;
        if (!DirNode::write(dirnode, &f2)) {
            cout << ". Writing main dirnode failed" << endl;
            return false;
        }
        f2.close();
    }

    cout << ". Everything looks ok" << endl;
    return true;
}

int main(int argc, char ** argv)
{
    google::InitGoogleLogging("--logtostderr=1");
    if (!check_main_dir()) {
        return -1;
    }
    setup_rx();

    return 0;
}
