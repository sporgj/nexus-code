#include "ucafs_tests.h"

sgx_enclave_id_t global_eid;

/**
 * Sets up the UCAFS test bed, makes debugging faster
 */
#define TESTBED_CONFIG "profile/repo.datum"

int start_testbed()
{
    if (ucafs_init_enclave()) {
        return -1;
    }

    if (ucafs_launch(TESTBED_CONFIG)) {
        return -1;
    }

    if (ucafs_init_uspace()) {
        return -1;
    }

    return 0;
}
