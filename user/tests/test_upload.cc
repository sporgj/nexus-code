#include <iostream>
#include <iomanip>
#include <fstream>

#include <sys/stat.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>

#include "defs.h"

extern "C" {
#include <afsx.h>
}

using namespace std;

#define AFSX_CUSTOM_PORT 11987

#define TEST_FILE (char *) "filetext.txt"
#define PAGE_SIZE 4096
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

// http://stackoverflow.com/questions/16804251/how-would-i-create-a-hex-dump-utility-in-c
static void hexdump(char * buf, uint32_t len)
{
    unsigned long address = 0;
    char c;

    cout << hex << setfill('0');
    while (len) {
        int nread = len > 16 ? 16 : len;

        // Show the address
        cout << setw(8) << address;

        // Show the hex codes
        for (int i = 0; i < 16; i++) {
            if (i % 8 == 0)
                cout << ' ';
            if (i < nread)
                cout << ' ' << setw(2) << (unsigned)buf[i];
            else
                cout << "   ";
        }

        // Show printable characters
        cout << "  ";
        for (int i = 0; i < nread; i++) {
            if (buf[i] < 32)
                cout << '.';
            else
                cout << buf[i];
        }

        cout << "\n";
        address += 16;

        buf += nread;
        len -= nread;
    }
}

static int test_upload()
{
    // start_srv();

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

    cout << ". Opening file" << endl;
    fstream input(TEST_FILE, ios::in);
    if (!input) {
        cout << "! Error reading file: " << TEST_FILE << endl;
        return -1;
    }

    struct rx_call * call = rx_NewCall(conn);
    size_t size = st.st_size, blklen = PAGE_SIZE;

    cout << ". Calling RPC" << endl;
    if (StartAFSX_fpush(call, TEST_FILE, blklen, st.st_size)) {
        cout << "Start RPC call failed" << endl;
        return -1;
    }

    char * buffer = (char *)operator new(blklen);
    int i = 0;
    while (size) {
        blklen = input.readsome(buffer, blklen);
        printf("Sending %d [%zd bytes]...\n", i, blklen);
        hexdump(buffer, HEXDUMP_LEN(blklen));
        rx_Write(call, buffer, blklen);
        printf("\nReceiving %d [%zd bytes]...\n", i, blklen);
        // read back from the wire
        rx_Read(call, buffer, blklen);
        hexdump(buffer, HEXDUMP_LEN(blklen));
        size -= blklen;
        i++;
    }

    EndAFSX_fpush(call);

    return 0;
}

int main(int argc, char ** argv)
{
    if (argc > 1) {
        start_srv();
        return 0;
    }
    int ret = test_upload();
    return ret;
}
