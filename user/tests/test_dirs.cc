#include "defs.h"
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;
#define N 1

static void mk_default_dnode()
{
    string * _str = uspace_main_dnode_fpath();
    DirNode * dn = new DirNode();

    cout << "Saving main dnode: " << _str->c_str() << endl;
    fstream f(_str->c_str(), ios::out);
    if (!DirNode::write(dn, &f)) {
        cout << "Could not save main file" << endl;
        return;
    }
    f.close();

    delete dn;
}

static int test_dirs()
{
    char buffer[50];
    char * name;

    for (size_t i = 0; i < N; i++) {
        sprintf(buffer, "img%d.jpeg", i);
        string curr_dir = "repo/";
        curr_dir += buffer;
        if (dirops_new(curr_dir.c_str(), UCAFS_TYPE_FILE, &name)) {
            printf("\n Failed\n");
            return -1;
        }

        printf("\r%s -> %s -> %d/%d", curr_dir.c_str(), name, i, N);
    }

    printf("\n");
    return 0;
}

int main()
{
    uspace_set_afs_home(TEST_AFS_HOME, nullptr, false);
    mk_default_dnode();
    test_dirs();
    return 0;
}
