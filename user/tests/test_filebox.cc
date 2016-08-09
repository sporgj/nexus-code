#include <iostream>

#include <encode.h>
#include <crypto.h>
#include <dirnode.h>

#include <glog/logging.h>

const char * test_dnode = "./dummy.dnode";

using namespace std;

const char * fnames[] = {"dell.md", "imac.txt", "firefox.app", "a.out", "vagrant/"};

static void test_filebox()
{
    LOG(INFO) << ". Initializing filebox file";
    // create our file and truncate it
    fstream file(test_dnode, ios::in | ios::out | ios::app);
    DirNode * fb = new DirNode();
    crypto_init_filebox(fb);
    fb->dump();
    DirNode::write(fb, &file);
    file.close();
    delete fb;

    LOG(INFO) << "Reading from initialized file";
    fb = DirNode::from_file(test_dnode, false);
    if (fb == nullptr) {
        LOG(ERROR) << "Error parsing dnode: " << test_dnode;
        return;
    }

    LOG(INFO) << "Adding entries to the filebox";
    for (size_t i = 0; i < sizeof(fnames)/sizeof(char *); i++) {
        crypto_add_file(fb, fnames[i]);
    }
    fb->dump();

    if (!DirNode::write(fb, test_dnode)) {
        LOG(ERROR) << "Flushing filebox failed";
        return;
    }
    delete fb;

    LOG(INFO) << "Rereading entries";
    fb = DirNode::from_file(test_dnode, false);
    if (fb == nullptr) {
        LOG(ERROR) << "Error parsing dnode: " << test_dnode;
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
