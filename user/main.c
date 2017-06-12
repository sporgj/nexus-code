/**
 *
 * UCAFS userland daemon process
 * @author judicael
 *
 */
#include <sys/stat.h>
#include <unistd.h>

#include "uc_dirnode.h"
#include "uc_vfs.h"
#include "uc_uspace.h"
#include "uc_utils.h"
#include "uc_sgx.h"

#define REPO_DATUM "profile/repo.datum"

FILE * global_mod_fid = NULL;

sgx_enclave_id_t global_eid = 0;

int setup_mod();

int main(int argc, char ** argv)
{
    int ret, updated;

    /* initialize the enclave */
    if (ucafs_init_enclave()) {
        return -1;
    }

    if (ucafs_launch(REPO_DATUM)) {
        uerror("launching repo failed");
        return -1;
    }

    if (ucafs_init_uspace()) {
        uerror("init uspace subsystem failed");
        return -1;
    }

#ifdef UCAFS_FLUSH
    uinfo("Flush ENABLED");
#else
    uinfo("Flush DISABLED");
#endif

    if (setup_mod()) {
        uerror(" ! Could not access module");
        return -1;
    }

    uinfo("Done...");

    while(1);

    return 0;
}
