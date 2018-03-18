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


static char *
__get_path_buffer(void)
{
    mutex_lock(&__path_buf_mutex);
    return __path_buf;
}


static void
__put_path_buffer(char * buffer)
{
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







/* the list of all paths watched */
LIST_HEAD(nexus_volumes_head);

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre);
    size_t lenstr = strlen(str);

    return (lenstr < lenpre) ? 0 : (strncmp(pre, str, lenpre) == 0);
}

int
nexus_add_volume(const char * path)
{
    struct nexus_volume_path * curr = NULL;
    int                        len  = strnlen(path, NEXUS_PATH_MAX);

    list_for_each_entry(curr, &nexus_volumes_head, list)
    {
        if (strncmp(curr->afs_path, path, curr->path_len) == 0) {
            return 0;
        }
    }

    /* if we are here, we need to add the entry to the list */
    curr = (struct nexus_volume_path *)kzalloc(
        sizeof(struct nexus_volume_path) + len, GFP_KERNEL);
    if (curr == NULL) {
        NEXUS_ERROR("allocation error, cannot add path to list");
        return -1;
    }

    curr->path_len = len;

    /* we should allow for paths that do not contain '/afs' */
    if (startsWith(AFS_PREFIX, path)) {
        strncpy(curr->afs_path, path + AFS_PREFIX_LEN, len - AFS_PREFIX_LEN);
    } else {
        strncpy(curr->afs_path, path, len);
    }

    list_add(&curr->list, &nexus_volumes_head);

    return 0;
}

void
nexus_clear_volume_list(void)
{
    struct nexus_volume_path * curr_wp = NULL;
    struct nexus_volume_path * prev_wp = NULL;

    list_for_each_entry_safe(curr_wp, prev_wp, &nexus_volumes_head, list)
    {
        list_del(&curr_wp->list);
        kfree(curr_wp);
    }

    INIT_LIST_HEAD(&nexus_volumes_head);
}

int
NEXUS_DISCONNECTED()
{
    return NEXUS_IS_OFFLINE;
}
