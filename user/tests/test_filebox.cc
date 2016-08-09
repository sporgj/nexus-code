#include <iostream>

#include <encode.h>
#include <crypto.h>
#include <filebox.h>

#include <glog/logging.h>

const char * test_fbox = "./dummy.fbox";

using namespace std;

const char * fnames[] = {"dell.md", "imac.txt", "firefox.app", "a.out", "vagrant/"};

static void test_filebox()
{
    LOG(INFO) << ". Initializing filebox file";
    // create our file and truncate it
    fstream file(test_fbox, ios::in | ios::out | ios::app);
    FileBox * fb = new FileBox();
    crypto_init_filebox(fb);
    fb->dump();
    FileBox::write(fb, &file);
    file.close();
    delete fb;

    LOG(INFO) << "Reading from initialized file";
    fb = FileBox::from_file(test_fbox, false);
    if (fb == nullptr) {
        LOG(ERROR) << "Error parsing fbox: " << test_fbox;
        return;
    }

    LOG(INFO) << "Adding entries to the filebox";
    for (size_t i = 0; i < sizeof(fnames)/sizeof(char *); i++) {
        crypto_add_file(fb, fnames[i]);
    }
    fb->dump();

    if (!FileBox::write(fb, test_fbox)) {
        LOG(ERROR) << "Flushing filebox failed";
        return;
    }
    delete fb;

    LOG(INFO) << "Rereading entries";
    fb = FileBox::from_file(test_fbox, false);
    if (fb == nullptr) {
        LOG(ERROR) << "Error parsing fbox: " << test_fbox;
        return;
    }
    fb->dump();
    delete fb;
}

int main() 
{
    FLAGS_colorlogtostderr = true;
    FLAGS_minloglevel = 0;
    FLAGS_logtostderr = true;
    google::InitGoogleLogging("--logtostderr=true --colorlogtostderr=true");

    test_filebox();
}
