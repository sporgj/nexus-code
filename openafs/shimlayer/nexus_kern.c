#include "nexus_module.h"

#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/string.h>

#include "nexus_kern.h"

static const char *   AFS_PREFIX     = "/afs";
static const uint32_t AFS_PREFIX_LEN = 4;





static char   __path_buf[PATH_MAX];
static DEFINE_MUTEX(__path_buf_mutex);


int
nexus_kern_init(void)
{
    mutex_init(&__path_buf_mutex);

    return 0;
}


void
nexus_kern_ping(void)
{
    // TODO
}


static char *
__get_path_buffer(void)
{
    mutex_lock(&__path_buf_mutex);
    return __path_buf;
}


static void
__put_path_buffer(char * buffer)
{
    (void) buffer;
    mutex_unlock(&__path_buf_mutex);
}


char *
nexus_get_path_from_dentry(struct dentry * dentry)
{
    char * afs_path    = NULL;
    char * tmp_path    = NULL;
    char * path_buffer = NULL;

    if (dentry == NULL) {
	NEXUS_DEBUG("Tried to get path from NULL dentry...\n");
	return NULL;
    }
    
    path_buffer = __get_path_buffer();

    if (path_buffer == NULL) {
	NEXUS_ERROR("Could not get path buffer\n");
	goto out1;
    }
    
    tmp_path = dentry_path_raw(dentry, path_buffer, PATH_MAX);

    if (IS_ERR_OR_NULL(tmp_path)) {
	NEXUS_ERROR("Could not decode dentry path\n");
	goto out2;
    }
    
    afs_path = kasprintf(GFP_KERNEL, "%s%s", AFS_PREFIX, tmp_path);

    if (afs_path == NULL) {
	NEXUS_ERROR("Could not allocate full path\n");
	goto out2;
    }
    
 out2:    
    __put_path_buffer(path_buffer);
 out1:
    return afs_path;
}


char * 
nexus_get_path_from_vcache(struct vcache * vcache)
{
    struct dentry * dentry = NULL;
    char          * path   = NULL;

    if ( (vcache             == NULL) ||
	 (vnode_type(vcache) == NEXUS_ANY) ) {
        return NULL;
    }

    /* this calls a dget(dentry) */
    dentry = d_find_alias(AFSTOV(vcache));

    /* maybe check that the dentry is not disconnected? */
    path = nexus_get_path_from_dentry(dentry);

    dput(dentry);
    
    return path;
}

int
NEXUS_DISCONNECTED()
{
    return NEXUS_IS_OFFLINE;
}
