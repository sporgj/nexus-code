#include <gtest/gtest.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <third/sds.h>

#include <cdefs.h>
#include <uc_dirnode.h>
#include <uc_dcache.h>
#include <uc_dirops.h>
#include <uc_uspace.h>

#ifdef __cplusplus
}
#endif

#define TEST_REPO_DIR "repo"

extern "C" void dcache_init();

static sds MK_PATH(const char * path)
{
    sds rv = sdsnew(TEST_REPO_DIR);
    rv = sdscat(rv, "/");
    rv = sdscat(rv, path);

    return rv;
}

static void
create_default_dnode()
{
    sds path = uc_main_dnode_fpath();
    uinfo("Creating: %s", path);
    uc_dirnode_t * dnode = dirnode_new();
    if (!dirnode_write(dnode, path)) {
        uerror("Could not write: %s", path);
    }

    sdsfree(path);
    dirnode_free(dnode);
}

static void
init_systems()
{
    uinfo("Initializing...");
    uc_set_afs_home(TEST_REPO_DIR, NULL, false);
    dcache_init();
}
