#include "defs.h"
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

using namespace std;
#define N 1024*16
#define AFSX_CUSTOM_PORT 11987

extern "C" {
#include <afsx.h>
}

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_rx(int);

static int start_srv()
{
    cout << "Starting server" << endl;
    setup_rx(AFSX_CUSTOM_PORT);
    return 0;
}

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

static int test_static_dirs()
{
    char buffer[50];
    char * name;

    for (size_t i = 0; i < N; i++) {
        sprintf(buffer, "img%d.jpeg", i);
        string curr_dir = "repo/";
        curr_dir += buffer;
        if (dirops_new(curr_dir.c_str(), UCAFS_TYPE_FILE, &name)) {
            printf("\n Failed\n");
            return -1;
        }

        printf("\r%s -> %s -> %d/%d", curr_dir.c_str(), name, i, N);
    }

    printf("\n");
    return 0;
}

static int test_rpc_dirs()
{
    char * encoded_name_str = NULL;
    u_long host;
    struct rx_securityClass * null_securityObject;
    char buffer[50];
    cout << ". Connecting... [localhost:" << AFSX_CUSTOM_PORT << "]" << endl;

    rx_Init(0);

    /* set the address to the current machine */
    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    struct rx_connection * conn = rx_NewConnection(host, AFSX_CUSTOM_PORT,
        AFSX_SERVICE_ID, null_securityObject, AFSX_NULL);

    mk_default_dnode();

    for (size_t i = 0; i < N; i++) {
        sprintf(buffer, "img%d.jpeg", i);
        string curr_dir = "repo/";
        curr_dir += buffer;
        if (AFSX_create(conn, (char *)curr_dir.c_str(), UCAFS_TYPE_FILE,
                &encoded_name_str)) {
            printf("\n Failed\n");
            return -1;
        }

        printf("\r%s -> %s -> %d/%d", curr_dir.c_str(), encoded_name_str, i, N);
    }

    return 0;
}

int main(int argc, char * argv[])
{
    uspace_set_afs_home("repo", NULL, false);

    if (argc > 1) {
        start_srv();
        return 0;
    }

    test_rpc_dirs();
    return 0;
}
