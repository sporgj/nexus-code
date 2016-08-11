#include "defs.h"

using namespace std;

const char * fnames[] = {"dell.md", "imac.txt", "firefox.app", "a.out", "vagrant/"};

static void test_dnode()
{
    LOG(INFO) << "Initializing dnode file";
    // create our file and truncate it
    fstream file(TEST_FBOX_PATH, ios::out | ios::trunc);
    DirNode * dn = new DirNode();
    DirNode::write(dn, &file);
    file.close();
    delete dn;

    LOG(INFO) << "Reading from initialized file";
    dn = DirNode::from_file(TEST_FBOX_PATH);
    if (dn == nullptr) {
        LOG(ERROR) << "Error parsing dnode: " << TEST_FBOX_PATH;
        return;
    }

    LOG(INFO) << "Adding entries to the dnode";
    for (size_t i = 0; i < sizeof(fnames)/sizeof(char *); i++) {
        dn->add_file(fnames[i]);
    }
    dn->list_files();

    if (!dn->flush()) {
        LOG(ERROR) << "Flushing dnode failed";
        return;
    }
    delete dn;

    LOG(INFO) << "Rereading entries";
    dn = DirNode::from_file(TEST_FBOX_PATH);
    if (dn == nullptr) {
        LOG(ERROR) << "Error parsing dnode: " << TEST_FBOX_PATH;
        return;
    }

    LOG(INFO) << "Listing entries";
    dn->list_files();

    delete dn;
}

int main() 
{
    FLAGS_colorlogtostderr = true;
    FLAGS_minloglevel = 0;
    FLAGS_logtostderr = true;
    google::InitGoogleLogging("--logtostderr=true --colorlogtostderr=true");

    test_dnode();
}
