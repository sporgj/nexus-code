#include "defs.h"
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

using namespace std;
#define N 5*1024
#define AFSX_CUSTOM_PORT 11987

extern "C" {
#include <afsx.h>
}

sgx_enclave_id_t global_eid = 0;

static void mk_default_dnode()
{
    sds _str = uc_main_dnode_fpath();
    struct dirnode * dn = dirnode_new();

    if (!dirnode_write(dn, _str)) {
        cout << "Could not save main file" << endl;
        return;
    }

    dirnode_free(dn);
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
        free(name);

        if (dirops_remove(curr_dir.c_str(), UCAFS_TYPE_FILE, &name)) {
            printf("Remove '%s' failed\n", curr_dir.c_str());
            return -1;
        }

        printf("\r%s -> %s -> %d/%d", curr_dir.c_str(), name, i, N);
        free(name);
    }

    printf("\n");
    return 0;
}

int main(int argc, char * argv[])
{
    uc_set_afs_home("repo", NULL, false);
    mk_default_dnode();
    dcache_init();

    test_static_dirs();
    return 0;
}
