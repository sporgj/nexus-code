/**
 *
 * UCAFS userland daemon process
 * @author judicael
 *
 */
#include <iostream>
#include <fstream>

#include <sys/stat.h>
#include <unistd.h>

#include "uc_dirnode.h"
#include "uc_dcache.h"
#include "uc_uspace.h"
#include "uc_sgx.h"

using namespace std;

#define REPO_DATUM "profile/repo.datum"

FILE * global_mod_fid = NULL;

sgx_enclave_id_t global_eid = 0;

extern "C" int setup_mod();

int main(int argc, char ** argv)
{
    int ret, updated;

    /* initialize the enclave */
    if (ucafs_init_enclave()) {
        return -1;
    }

    if (ucafs_launch(REPO_DATUM)) {
        cout << "launching repo failed" << endl;
        return -1;
    }

    if (ucafs_init_uspace()) {
        cout << "init uspace subsystem failed" << endl;
        return -1;
    }

    if (setup_mod()) {
        cout << " ! Could not access module" << endl;
        return -1;
    }

    cout << "Done..." << endl;

    while(1);

    return 0;
}
