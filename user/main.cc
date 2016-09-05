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

#include "dirnode.h"
#include "uspace.h"

using namespace std;

extern "C" int setup_rx(int);

const char afs_path[] = "/afs/maatta.sgx/user/bruyne";
static bool check_main_dir()
{
    string afsx_repo(afs_path);
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

    string * afsx_dnode = get_default_dnode_fpath();
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
    set_global_afs_home_path(afs_path);
    google::InitGoogleLogging("--logtostderr=1");
    if (!check_main_dir()) {
        return -1;
    }
    setup_rx(0);

    return 0;
}
