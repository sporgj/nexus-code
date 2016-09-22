#include "defs.h"

using namespace std;

const char * fnames[]
    = { "mellow/index.html", "/afs/maatta.sgx/bruyne/firefox.exe",
        "./Xcode.app", "hello/terminal.bin" };

const char * alias_names[] = { "index.html", "index.html~" };

#define LEN sizeof(fnames) / sizeof(char *)
#define SIMLEN sizeof(alias_names) / sizeof(char *)

static void test_dops()
{
    char * str, * codenames[LEN];
}

int main()
{
    return 0;
}

#if 0
static void test_alias()
{
    char * str;
    char * codenames[SIMLEN];

    cout << ". Initializing filebox file" << endl;
    // create our file and truncate it
    fstream file(TEST_FBOX_PATH1, ios::out | ios::trunc);
    DirNode * dn = new DirNode();
    DirNode::write(dn, &file);
    file.close();
    delete dn;

    for (size_t i = 0; i < SIMLEN; i++) {
        cout << alias_names[i];
        if (fops_new((char *)alias_names[i], &str)) {
            cout << " FAILED" << endl;
            return;
        }
        codenames[i] = str;
        cout << " =====> " << str << endl;
    }

    cout << ". Removing entries" << endl;
    fops_plain2code((char *)alias_names[0], &str);
    cout << alias_names[0] << " ~> " << str << endl;

    fops_plain2code((char *)alias_names[1], &str);
    cout << alias_names[1] << " ~> " << str << endl;
}

static void test_dops()
{
    char * str;
    char * codenames[LEN];

    cout << ". Initializing filebox file" << endl;
    // create our file and truncate it
    fstream file(TEST_FBOX_PATH1, ios::out | ios::trunc);
    DirNode * dn = new DirNode();
    DirNode::write(dn, &file);
    file.close();
    delete dn;

    cout << "\n. Adding entries to the filebox " << endl;
    for (size_t i = 0; i < LEN; i++) {
        cout << fnames[i];
        if (fops_new((char *)fnames[i], &str)) {
            cout << " FAILED" << endl;
            return;
        }
        codenames[i] = str;
        cout << " =====> " << str << endl;
    }

    cout << "\n. Filldir operation (encoded -> plain)" << endl;
    for (size_t i = 0; i < LEN; i++) {
        cout << codenames[i];
        if (fops_code2plain(codenames[i], (char *)"", &str)) {
            cout << " FAILED" << endl;
            return;
        }
        cout << " ======> " << str << endl;
    }

    cout << "\n. Lookup operation (plain -> encoded)" << endl;
    for (size_t i = 0; i < LEN; i++) {
        cout << fnames[i];
        if (fops_plain2code((char *)fnames[i], &str)) {
            cout << " FAILED" << endl;
            return;
        }
        cout << " ======> " << str << endl;
    }

    dn = DirNode::from_file(TEST_FBOX_PATH1);

    cout << "\n. Listing entries" << endl;
    dn->list_files();

    cout << "\n. Deleting entries" << endl;
    srand(time(0));
    for (size_t i = 0; i < 2; i++) {
        int j = rand() % LEN;
        cout << "Removing '" << fnames[j] << "'... ";
        if (fops_remove((char *)fnames[j], &str)) {
            cout << "FAILED" << endl;
            ;
            continue;
        }
        cout << str << endl;
    }

    cout << "\n. Listing entries" << endl;
    dn = DirNode::from_file(TEST_FBOX_PATH1);
    dn->list_files();
}

int main()
{
    FLAGS_colorlogtostderr = true;
    FLAGS_minloglevel = 0;
    FLAGS_logtostderr = true;
    google::InitGoogleLogging("--logtostderr=true --colorlogtostderr=true");

    test_dops();
    test_alias();
}
#endif
