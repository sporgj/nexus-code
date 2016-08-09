#include <iostream>

#include <encode.h>
#include <crypto.h>
#include <dirnode.h>

#include <glog/logging.h>

const char * fnames[]
    = { "index.html", "firefox.exe", "Xcode.app", "terminal.bin" };

using namespace std;

static void test_crypto()
{
    const char * codenames[sizeof(fnames)];
    encoded_fname_t * encoded_name;
    class ::DirNode * fb = new class ::DirNode;
    crypto_init_filebox(fb);

    cout << ". Adding files..." << endl;
    for (size_t i = 0; i < sizeof(fnames) / sizeof(char *); i++) {
        encoded_name = crypto_add_file(fb, fnames[i]);
        codenames[i] = encode_bin2str(encoded_name);
        cout << fnames[i] << " ~> " << codenames[i] << endl;
    }

    cout << "\n. Looking up by codenames" << endl;
    for (size_t i = 0; i < sizeof(fnames) / sizeof(char *); i++) {
        encoded_name = encode_str2bin(codenames[i]);
        if (encoded_name == NULL) {
            LOG(ERROR) << "Encoded name: '" << codenames[i] << "' is invalid";
            return;
        }
        const char * raw_name = crypto_get_fname(fb, encoded_name);

        cout << codenames[i] << " ==>> " << raw_name << endl;
    }

    cout << "\n . Reverse Lookup of plain to codenames" << endl;
    for (size_t i = 0; i < sizeof(fnames) / sizeof(char *); i++) {
        encoded_name = crypto_get_codename(fb, fnames[i]);
        if (encoded_name == NULL) {
            cout << fnames[i] << " could not be found :<" << endl;
        } else {
            const char * codename_str = encode_bin2str(encoded_name);
            cout << fnames[i] << " ~> " << codename_str << endl;
        }
    }

    LOG(INFO) << "SUCCESS";
}

int main()
{
    google::InitGoogleLogging("--logtostderr=1 --colorlogtostderr=1");

    test_crypto();
}
