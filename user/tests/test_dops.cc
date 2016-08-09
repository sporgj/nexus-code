#include "defs.h"

using namespace std;

const char * fnames[] = { "mellow/index.html", "/afs/maatta.sgx/bruyne/firefox.exe",
                    "./Xcode.app", "hello/terminal.bin" };

#define LEN sizeof(fnames)/sizeof(char *)

static void test_dops()
{
    char * str;
    char * codenames[LEN];

    cout << ". Initializing filebox file" << endl;
    // create our file and truncate it
    fstream file(gbl_temp_dnode_path, ios::in | ios::out | ios::app);
    DirNode * fb = new DirNode();
    crypto_init_filebox(fb);
    DirNode::write(fb, &file);
    file.close();
    delete fb;

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

    cout << "\n . Lookup operation (plain -> encoded)" << endl;
    for (size_t i = 0; i < LEN; i++) {
        cout << fnames[i];
        if (fops_plain2code((char *)fnames[i], &str)) {
            cout << " FAILED" << endl;
            return;
        }
        cout << " ======> " << str << endl;
    }

    cout << "\n . Deleting entries" << endl;
    srand(time(0));
    for (size_t i = 0; i < 2; i++) {
        int j = rand() % LEN;
        cout << "Removing '" << fnames[j] << "'... ";
        if (fops_remove((char *)fnames[j], &str)) {
            cout << "FAILED";
        }
        cout << str << endl;
    }
    
    fb = DirNode::from_path(TEST_FBOX_PATH1, true);
    crypto_list_files(fb);
}

int main()
{
    FLAGS_colorlogtostderr = true;
    FLAGS_minloglevel = 0;
    FLAGS_logtostderr = true;
    google::InitGoogleLogging("--logtostderr=true --colorlogtostderr=true");

    test_dops();
}
