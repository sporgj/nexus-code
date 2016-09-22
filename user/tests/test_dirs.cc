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

        if (dirops_new(curr_dir.c_str(),
                       ((curr_dir.find('.') == std::string::npos)
                            ? UCAFS_TYPE_DIR
                            : UCAFS_TYPE_FILE),
                       &encoded_name)) {
            return -1;
        }

        cout << curr_dir << " \t " << encoded_name << endl;

        return build_tree(curr_dir, i + 1, j);
    }

    return 0;
}

int test_dirs()
{
    int ret;
    char * temp, *temp2;
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

    string dir1("repo/alice/bob"), dir2("repo/alice/kilda");
    cout << endl;
    cout << "Renaming '" << dir1 << "' to '" << dir2 << "'" << endl;
    if ((ret
         = dirops_rename(dir1.c_str(), dir2.c_str(), UCAFS_TYPE_DIR, &temp))) {
        cout << "FAILED. ret = " << ret << endl;
        return -1;
    }
    cout << "PASSED" << endl;

#if 0
    string dir1("repo/alice/bob"), dir2("repo/alice/kilda");
    /*dir1 += "/";
    dir1 += lvl[0][2];
    dir2 += "/";
    dir2 += "pro";*/

    cout << endl;
    cout << "Renaming '" << dir1 << "' to '" << dir2 << "'" << endl;
    if ((ret = dirops_rename(dir1.c_str(), dir2.c_str(), AFSX_IS_DIR, &temp))) {
        cout << "FAILED. ret = " << ret << endl;
        return -1;
    }
    cout << "PASSED" << endl;

    string f1("repo/foo"), f2("repo/foo");
    f1 += "/";
    f2 += "/";
    f1 += "config.lock";
    f2 += "config";

    cout << "Creating: " << f1 << "\t";
    if (fops_new(f1.c_str(), &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f1 << "\t";
    if (fops_plain2code(f1.c_str(), &temp)) {
        cout << "not found" << endl;
    } else {
        cout << temp << endl;
    }

    cout << "Renaming '" << f1 << "' -> '" << f2 << "'" << endl;
    if (dirops_rename(f1.c_str(), f2.c_str(), AFSX_IS_FILE, &temp)) {
        cout << "Error" << endl;
        return -1;
    }

    cout << "Finding: " << f1 << "\t";
    if (fops_plain2code(f1.c_str(), &temp)) {
        cout << "Success" << endl;
    } else {
        cout << "Error" << endl;
        return -1;
    }

    cout << "Recreaing: " << f1 << "\t";
    if (fops_new(f1.c_str(), &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f1 << "\t";
    if (fops_plain2code(f1.c_str(), &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f2 << "\t";
    if (fops_plain2code(f2.c_str(), &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;
#endif

    return 0;
}

int main()
{
    uspace_set_afs_home(TEST_AFS_HOME, nullptr, false);
    mk_default_dnode();
    srand(time(NULL));
    test_dirs();
    return 0;
}
