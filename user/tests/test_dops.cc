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
    sds _str = uc_main_dnode_fpath();
    struct dirnode * dn = dirnode_new();

    if (!dirnode_write(dn, _str)) {
        cout << "Could not save main file" << endl;
        return;
    }

    dirnode_free(dn);
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

    string f1("repo/foo"), f2("repo/foo");
    f1 += "/";
    f2 += "/";
    f1 += "config.lock";
    f2 += "config";

    cout << "Creating: " << f1 << "\t";
    if (dirops_new(f1.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f1 << "\t";
    if (dirops_plain2code(f1.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "not found" << endl;
        return -1;
    } else {
        cout << temp << endl;
    }

    cout << "Finding: " << f2 << "\t";
    if (dirops_plain2code(f2.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "not found" << endl;
    } else {
        cout << temp << "\t ERROR" << endl;
        return -1;
    }

    cout << "Renaming '" << f1 << "' -> '" << f2 << "'" << endl;
    if (dirops_rename(f1.c_str(), f2.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "Error" << endl;
        return -1;
    }

    cout << "Finding: " << f1 << "\t";
    if (dirops_plain2code(f1.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "Success" << endl;
    } else {
        cout << "Error" << endl;
        return -1;
    }

    cout << "Recreating: " << f1 << "\t";
    if (dirops_new(f1.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f1 << "\t";
    if (dirops_plain2code(f1.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    cout << "Finding: " << f2 << "\t";
    if (dirops_plain2code(f2.c_str(), UCAFS_TYPE_FILE, &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }
    cout << temp << endl;

    string f3("repo/foo");
    cout << "Removing: " << f3 << "\t";
    if (dirops_remove(f3.c_str(), UCAFS_TYPE_DIR, &temp)) {
        cout << "FAILED" << endl;
        return -1;
    }

    cout << "WORKED" << endl;

    return 0;
}

int main()
{
    uc_set_afs_home(TEST_AFS_HOME, nullptr, false);
    dcache_init();
    mk_default_dnode();
    srand(time(NULL));
    test_dirs();
    return 0;
}
