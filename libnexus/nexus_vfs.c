#include "nexus_untrusted.h"

struct nx_volume_list * nx_volume_head = NULL;

int
nexus_vfs_init()
{
    int ret = -1;

    log_debug("Initializing the NeXUS virtual filesystem");

    //
    nx_volume_head
        = (struct nx_volume_list *)calloc(1, sizeof(struct nx_volume_list));
    if (nx_volume_head == NULL) {
        log_error("allocation error");
        goto out;
    }

    TAILQ_INIT(nx_volume_head);

    ret = 0;
out:
    return ret;
}

int
nexus_vfs_add_volume(struct supernode_header * supernode_header,
                     const char *              metadata_dir,
                     const char *              data_dir)
{
    int                     ret                = -1;
    char *                  root_dirnode_fpath = NULL;
    struct nx_volume_item * volume_item        = NULL;

    volume_item
        = (struct nx_volume_item *)calloc(1, sizeof(struct nx_volume_item));
    if (volume_item == NULL) {
        log_error("allocation error");
        return -1;
    }

    volume_item->metadata_dir = strndup(metadata_dir, PATH_MAX);
    if (volume_item->metadata_dir == NULL) {
        log_error("allocation error");
        goto out;
    }

    volume_item->datafile_dir = strndup(data_dir, PATH_MAX);
    if (volume_item->datafile_dir == NULL) {
        log_error("allocation error");
        goto out;
    }

    // precompute the lengths
    volume_item->metadata_dir_len
        = strnlen(volume_item->metadata_dir, PATH_MAX);
    volume_item->datafile_dir_len
        = strnlen(volume_item->datafile_dir, PATH_MAX);

    // assign the path to the root dirnode
    volume_item->root_dirnode_fpath
        = uuid_path(metadata_dir, &supernode_header->root_uuid);

    memcpy(&volume_item->supernode_header,
           supernode_header,
           sizeof(struct supernode_header));

    TAILQ_INSERT_TAIL(nx_volume_head, volume_item, next_item);

    ret = 0;
out:
    if (ret) {
        nexus_free2(root_dirnode_fpath);
        nexus_free2(volume_item->metadata_dir);
        nexus_free2(volume_item);
    }

    return ret;
}

const char *
nexus_vfs_root_dirnode_fpath(const char * path)
{
    int                     len         = 0;
    struct nx_volume_item * volume_item = NULL;

    TAILQ_FOREACH(volume_item, nx_volume_head, next_item)
    {
        len = volume_item->datafile_dir_len;
        if (memcmp(path, volume_item->datafile_dir, len) == 0) {
            return volume_item->root_dirnode_fpath;
        }
    }

    return NULL;
}

struct nx_inode *
nexus_get_inode(const char * path)
{
    int               err                = -1;
    size_t            size               = 0;
    uint8_t *         buffer             = NULL;
    const char *      root_dirnode_fpath = NULL;
    struct dirnode *  dirnode            = NULL;
    struct nx_inode * inode              = NULL;

    root_dirnode_fpath = nexus_vfs_root_dirnode_fpath(path);
    if (root_dirnode_fpath == NULL) {
        return NULL;
    }

    inode = (struct nx_inode *)calloc(1, sizeof(struct nx_inode));
    if (inode == NULL) {
        log_error("allocation failed");
        return NULL;
    }

    err = read_file(root_dirnode_fpath, &buffer, &size);
    if (err != 0) {
        log_error("read_file FAILED");
        goto out;
    }

    dirnode = (struct dirnode *)buffer;

    // TODO add code for filebox
    inode->type    = NEXUS_DIRNODE;
    inode->dirnode = dirnode;
    inode->fpath   = uuid_path(path, &dirnode->header.uuid);

    err = 0;
out:
    if (err != 0) {
        nexus_free2(inode);
    }

    return inode;
}

// TODO
int
nexus_put_inode(struct nx_inode * inode)
{
    nexus_free2(inode->fpath);
    nexus_free2(inode->dirnode);
    nexus_free2(inode);

    return 0;
}

int
nexus_flush_dirnode(struct nx_inode * inode, struct dirnode * dirnode)
{
    int ret = -1;

    ret = write_file(inode->fpath, dirnode, dirnode->header.total_size);
    if (ret != 0) {
	log_error("could not write dirnode (%s)", inode->fpath);
	goto out;
    }

    // free the current inode dirnode and cache the new
    nexus_free2(inode->dirnode);
    inode->dirnode = dirnode;
out:
    return ret;
}

// TODO
void
nexus_vfs_exit()
{
    // free the nx_volume_list
}
