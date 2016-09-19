#include "defs.h"

using namespace std;

const char * folders[] = { "future", "drake", "jeezy" },
             *files[] = { "plug.txt", "dash.md", "jersey.doc" },
	     *folders2 = "skinner";

int save_file(const char * fname, const encoded_fname_t * ename)
{
    int num = 2;
    const char * estr = encode_bin2str(ename);
    string * dest_path = uspace_make_dnode_fpath(estr);
    fstream fp(dest_path->c_str(), ios::out);
    DirNode * dn = new DirNode();
    if (strcmp(fname, folders[2]) == 0) {
	for (size_t i = 0; i < sizeof(files)/sizeof(char *); i++) {
	    dn->add_file(files[i]);
	}
    }

    if (!DirNode::write(dn, &fp)) {
	cout << "Could not save: " << dest_path->c_str() << endl;
	return num;
    }
    cout << fname << " ~> " << dest_path->c_str() << endl;
    fp.close();

    return num;
}

void test_lookup()
{
    string * main_dnode_str = uspace_main_dnode_fpath();
    DirNode * dn = new DirNode();
    const encoded_fname_t * ename;
    int num;

    cout << endl;
    cout << "Adding folders" << endl;
    for (size_t i = 0; i < sizeof(folders)/sizeof(char *); i++) {
        ename = dn->add_dir(folders[i]);
	num = save_file(folders[i], ename);
    }

    dn->list_files();

    cout << "Saving main dnode: " << main_dnode_str->c_str() << endl;
    fstream f(main_dnode_str->c_str(), ios::out);
    if (!DirNode::write(dn, &f)) {
        cout << "Could not save main file" << endl;
        return;
    }
    f.close();

    cout << "Adding files in subdirs" << endl;
    string path(folders[num]);
    path += "/";
    path += files[2];

    cout << "Looking up: " << path << endl;
    DirNode * dn2 = DirNode::lookup_path(path.c_str());
    if (dn2 == nullptr) {
	cout << "not found" << endl;
	return;
    }
    cout << "Listing dirs: " << endl;
    dn2->list_files();
}

int main()
{
    uspace_set_afs_home(TEST_AFS_HOME, false);
    test_lookup();

    return 0;
}
