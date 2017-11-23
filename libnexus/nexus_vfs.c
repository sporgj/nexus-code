#include "nexus_untrusted.h"
#include <sys/stat.h>
#include <unistd.h>

struct nx_volume_list * nx_volume_head = NULL;

int
nexus_vfs_init()
{
    int ret = -1;

    log_debug("Initializing the NeXUS virtual filesystem");

    compute_encoded_str_size();

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
    struct nx_dentry *      root_dentry        = NULL;

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

    // allocate the root dentry
    root_dentry = (struct nx_dentry *)calloc(1, sizeof(struct nx_dentry));
    if (root_dentry == NULL) {
        log_error("allocation error");
        goto out;
    }

    memcpy(
        &root_dentry->uuid, &supernode_header->root_uuid, sizeof(struct uuid));

    root_dentry->volume      = volume_item;
    volume_item->root_dentry = root_dentry;

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
        // TODO move this to a "free volume" function
        nexus_free2(root_dirnode_fpath);
        nexus_free2(root_dentry);

        nexus_free2(volume_item->metadata_dir);
        nexus_free2(volume_item->datafile_dir);
        nexus_free2(volume_item);
    }

    return ret;
}

/**
 * Returns the volume item that corresponds to the path
 * @param path
 * @param {optional} p_relpath the resultant relative path from the root
 * @return NULL on failure
 */
struct nx_volume_item *
nexus_vfs_get_volume(const char * path, char ** p_relpath)
{
    int                     len         = 0;
    const char *            strptr      = NULL;
    struct nx_volume_item * volume_item = NULL;

    TAILQ_FOREACH(volume_item, nx_volume_head, next_item)
    {
        len = volume_item->datafile_dir_len;
        if (memcmp(path, volume_item->datafile_dir, len) == 0) {

            if (p_relpath) {
                // XXX there might be a smarter way to do this
                strptr = path + len;
                if (*strptr == '/') {
                    strptr++;
                }

                *p_relpath = strndup(strptr, PATH_MAX);
            }

            return volume_item;
        }
    }

    return NULL;
}

const char *
nexus_vfs_root_dirnode_fpath(const char * path)
{
    const struct nx_volume_item * volume_item = NULL;

    volume_item = nexus_vfs_get_volume(path, NULL);

    return volume_item ? volume_item->root_dirnode_fpath : NULL;
}

struct nx_inode *
vfs_get_inode(const char * path)
{
    struct nx_dentry * dentry = nexus_vfs_lookup(path);
    return dentry ? dentry->inode : NULL;
}

struct nx_inode *
nexus_load_inode(struct nx_dentry * dentry, struct path_builder * builder)
{
    return NULL;
}

// TODO
int
vfs_put_inode(struct nx_inode * inode)
{
    nexus_free2(inode->fpath);
    nexus_free2(inode->dirnode);
    nexus_free2(inode);

    return 0;
}

int
vfs_flush_dirnode(struct nx_inode * inode, struct dirnode * dirnode)
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

int
vfs_create_inode(struct nx_inode * parent_inode,
                 struct uuid *     uuid,
                 nx_inode_type_t   type)
{
    int    ret           = -1;
    char * metadata_name = NULL;
    char * fullpath      = NULL;
    FILE * fd            = NULL;

    metadata_name = metaname_bin2str(uuid);
    if (metadata_name == NULL) {
        log_error("metaname_bin2str FAILED");
        return -1;
    }

    // if it's a root dirnode, the metadata file is in the metadata_dir
    if (parent_inode->is_root_dirnode) {
        fullpath = strndup(parent_inode->volume->metadata_dir, PATH_MAX);
        fullpath = pathjoin(fullpath, metadata_name);
    } else {
        fullpath = strndup(parent_inode->fpath, PATH_MAX);
        fullpath = my_strnjoin(fullpath, "_/", metadata_name, PATH_MAX);
    }

    // save the metadata file
    fd = fopen(fullpath, "wb");
    if (fd == NULL) {
        log_error("fopen('%s') FAILED", fullpath);
        goto out;
    }

    fclose(fd);
    fd = NULL;

    if (type == NEXUS_DIRNODE) {
        // create the dirnode directory
        fullpath = my_strnjoin(fullpath, NULL, "_", PATH_MAX);

        ret = mkdir(fullpath, S_IRWXG);
        if (ret != 0 && ret != EEXIST) {
            log_error("creating dirnode directory (%s)", fullpath);
            goto out;
        }

        // just in case we have EEXIST from above
        ret = 0;
    }

    ret = 0;
out:
    nexus_free2(metadata_name);
    nexus_free2(fullpath);

    if (fd) {
        fclose(fd);
    }

    return ret;
}

struct nx_inode *
vfs_read_inode(struct nx_dentry * dentry, struct path_builder * builder)
{
    int               err       = -1;
    int               ret       = -1;
    size_t            size      = 0;
    uint8_t *         buffer    = NULL;
    char *            fullpath  = NULL;
    struct dirnode *  dirnode   = NULL;
    struct nx_inode * inode     = NULL;
    struct uuid *     uuid      = &dentry->uuid;
    struct uuid *     root_uuid = &dentry->volume->supernode_header.root_uuid;

    // add the path to the file and form the string
    path_push(builder, uuid);
    fullpath = path_string(builder, dentry->volume->metadata_dir);
    path_pop(builder);

    err = read_file(fullpath, &buffer, &size);
    if (err != 0) {
        log_error("read_file FAILED");
        goto out;
    }

    inode = (struct nx_inode *)calloc(1, sizeof(struct nx_inode));
    if (inode == NULL) {
        log_error("allocation failed");
        return NULL;
    }

    // if the file is empty, then we've to instantiate a new inode
    if (size == 0) {
        nexus_free2(buffer);

        dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode *));
        if (dirnode == NULL) {
            log_error("allocation error");
            goto out;
        }

        err = ecall_dirnode_new(global_enclave_id, &ret, uuid, root_uuid, dirnode);
        if (err || ret) {
            err |= ret;
            log_error("ecall_dirnode_new() FAILED");
            goto out;
        }
    } else {
        dirnode = (struct dirnode *)buffer;
    }

    // TODO add code for filebox
    inode->type    = NEXUS_DIRNODE;
    inode->dirnode = dirnode;
    inode->fpath   = fullpath;
    inode->volume  = dentry->volume;
    inode->is_root_dirnode = (dentry->parent == NULL);

    dentry->inode = inode;

    err = 0;
out:
    if (err) {
        nexus_free2(fullpath);
        nexus_free2(dirnode);
        nexus_free2(inode);
        return NULL;
    }

    return inode;
}

void
vfs_refresh_inode(struct nx_inode * inode)
{
    // TODO
}

struct nx_dentry *
nexus_vfs_lookup(const char * path)
{
    char *                        relpath = NULL;
    const struct nx_volume_item * volume  = NULL;
    struct nx_dentry *            dentry  = NULL;

    volume = nexus_vfs_get_volume(path, &relpath);
    if (volume == NULL) {
        log_error("nexus_vfs_get_volume() FAILED");
        return NULL;
    }

    dentry = nexus_dentry_lookup(volume->root_dentry, relpath);

    nexus_free2(relpath);

    return dentry;
}

// TODO
void
nexus_vfs_exit()
{
    // free the nx_volume_list
}
