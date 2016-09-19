#include "defs.h"
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstring>

using namespace std;

#define X 4
#define Y 3

const char * lvl[X][Y] = { { "alice", "foo", "bar" },
                           { "bob", NULL, "oops" },
                           { "file.md", NULL, "read.txt" },
                           { NULL, NULL, NULL } };
vector<char *> check_paths;

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

int build_tree(string & curr_dir, int i, int j)
{
    char * encoded_name;

    if (lvl[i][j]) {
        curr_dir += "/";
        curr_dir += lvl[i][j];

        if (curr_dir.find('.') == std::string::npos) {
            cout << "d: " << curr_dir << " \t ";
            if (dops_new(curr_dir.c_str(), &encoded_name)) {
                return -1;
            }
        } else {
            cout << "f: " << curr_dir << " \t ";
            if (fops_new(curr_dir.c_str(), &encoded_name)) {
                return -1;
            }
        }

        cout << encoded_name << endl;

        if (rand() % 2) {
            check_paths.push_back(strdup(curr_dir.c_str()));
        }

        return build_tree(curr_dir, i + 1, j);
    }

    return 0;
}

int test_dirs()
{
    int ret;
    char * temp;
    /* 1 - building the directory tree */
    for (size_t k = 0; k < Y; k++) {
        string v = string(TEST_AFS_HOME);
        if ((ret = build_tree(v, 0, k))) {
            cout << " ! Failed. ret = " << ret << endl;
            return -1;
        }

        cout << endl;
    }

    /* 2 - Loooking up directories */
    for (size_t k = 0; k < check_paths.size(); k++) {
        cout << check_paths[k] << endl;
    }

    /* 3 - let's try removing */
    string dir("repo");
    dir += "/";
    dir += lvl[0][0];

    /*
    cout << endl;
    cout << "Removing: " << dir << endl;
    if (dops_remove(dir.c_str(), &temp)) {
        cout << "Failed" << endl;
    } else {
        cout << "PASSED. Removed: " << temp << endl;
    }
    */

    string dir1("repo/alice/bob"), dir2("repo/alice/kilda");
    /*dir1 += "/";
    dir1 += lvl[0][2];
    dir2 += "/";
    dir2 += "pro";*/

    cout << endl;
    cout << "Renaming '" << dir1 << "' to '" << dir2 << "'" << endl;
    if ((ret = dops_rename(dir1.c_str(), dir2.c_str(), &temp))) {
        cout << "FAILED. ret = " << ret << endl;
        return -1;
    }

    return 0;
}

int main()
{
    uspace_set_afs_home(TEST_AFS_HOME, false);
    mk_default_dnode();
    srand(time(NULL));
    test_dirs();
    return 0;
}
