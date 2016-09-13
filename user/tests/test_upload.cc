#include <iostream>
#include <iomanip>
#include <fstream>

#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>

#include <sgx_urts.h>

#include "defs.h"
#define ENCLAVE_FILENAME "../sgx/enclave.signed.so"

extern "C" {
#include <afsx.h>
}

sgx_enclave_id_t global_eid = 0;

using namespace std;

#define AFSX_CUSTOM_PORT 11987

#define TEST_FILE (char *) "filetext.txt"
#define PACKET_SIZE 4096
#define HEXDUMP_LEN(d) (d > 32 ? 32 : d)

extern "C" int setup_rx(int);

static int start_srv()
{
    cout << "Starting server" << endl;
    pid_t pid = 0; // fork();

    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        setup_rx(AFSX_CUSTOM_PORT);
    }

    return 0;
}

static void init_dnode()
{
    cout << ". Initializing filebox file" << endl;
    // create our file and truncate it
    fstream file(uspace_get_dnode_fpath()->c_str(), ios::out | ios::trunc);
    DirNode * dn = new DirNode();
    DirNode::write(dn, &file);
    file.close();
}

static int test_upload()
{
    // start_srv();
    int moredata;
    uint32_t padded_len;
    char * encoded_name_str;
    u_long host;
    struct rx_securityClass * null_securityObject;

    rx_Init(0);

    cout << ". Connecting... [localhost:" << AFSX_CUSTOM_PORT << "]" << endl;
    /* set the address to the current machine */
    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    struct rx_connection * conn
        = rx_NewConnection(host, AFSX_CUSTOM_PORT, AFSX_SERVICE_ID,
                           null_securityObject, AFSX_NULL);

    struct stat st;
    if (stat(TEST_FILE, &st)) {
        cout << "Could not stat: " << TEST_FILE << endl;
        return -1;
    }

    int result;
    if (AFSX_fversion(conn, 4, &result)) {
        cout << "Can't computer " << endl;
        return -1;
    }

    // lets add it to a fake dnode
    init_dnode();
    if (fops_new(TEST_FILE, &encoded_name_str)) {
        cout << "Adding to dnode failed" << endl;
        return -1;
    }

    cout << ". Opening file" << endl;
    fstream input(TEST_FILE, ios::in);
    if (!input) {
        cout << "! Error reading file: " << TEST_FILE << endl;
        return -1;
    }

    afs_uint32 size = st.st_size, blklen = PACKET_SIZE, upload_id;

    if ((result = AFSX_readwrite_start(conn, UCAFS_READOP, TEST_FILE, blklen,
                                       size, &upload_id, &padded_len))) {
        cout << "Start RPC call failed: " << result << endl;
        return -1;
    }

    cout << "Starting upload. id=" << upload_id << " flen=" << size
         << " padlen=" << padded_len << endl;

    char * buffer = (char *)operator new(PACKET_SIZE);
    afs_uint32 nbytes, buflen;
    while (padded_len > 0) {
        blklen = size > PACKET_SIZE ? PACKET_SIZE : size;
        // read from the file
        buflen = input.readsome(buffer, blklen);

        // recompute to include the padding
        if (blklen < PACKET_SIZE) {
            blklen = padded_len;
        }

        struct rx_call * call = rx_NewCall(conn);

        if (StartAFSX_readwrite_data(call, upload_id, blklen)) {
            cout << "StartAFSX_upload_file failed" << endl;
            return -1;
        }

        printf("\nSending [%zd bytes]...\n", blklen);
        hexdump((uint8_t *)buffer, HEXDUMP_LEN(blklen));

        if ((nbytes = rx_Write(call, buffer, blklen)) != blklen) {
            cout << "send error: expected: " << blklen << ", actual: " << nbytes
                 << endl;
            return -1;
        }

        printf("Receiving [%zd bytes]...\n", blklen);
        if ((nbytes = rx_Read(call, buffer, blklen)) != blklen) {
            cout << "Receive error: expected: " << blklen
                 << ", actual: " << nbytes << endl;
            return -1;
        }

        hexdump((uint8_t *)buffer, HEXDUMP_LEN(blklen));
        size -= blklen;
        padded_len -= blklen;

        EndAFSX_readwrite_data(call, &moredata);
        rx_EndCall(call, 0);
    }
    return 0;
}

int main(int argc, char ** argv)
{
    int ret, updated;
    uspace_set_afs_home("repo", false);
    /* initialize the enclave */
    sgx_launch_token_t token;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        cout << "Could not open enclave: " << ENCLAVE_FILENAME
             << ", ret=" << ret << endl;
        return -1;
    }

    // initialize
    ecall_init_enclave(global_eid, &ret);
    if (ret) {
        cout << "Initializing enclave failed" << endl;
        return -1;
    }

    cout << "Initialized enclave" << endl;

    if (argc > 1) {
        start_srv();
        return 0;
    }

    cout << ". Loaded enclave" << endl;
    return test_upload();
}
