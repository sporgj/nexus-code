#include "nexus_fuse.h"

struct nexus_dirent *
nexus_fuse_readdir(struct my_dentry * dentry,
                   size_t             offset,
                   size_t           * result_count,
                   size_t           * directory_size)
{
    size_t dirent_count = 128;

    struct nexus_dirent * result = nexus_malloc(dirent_count * sizeof(struct nexus_dirent));


    char * dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return NULL;
    }

    if (nexus_fs_readdir(nexus_fuse_volume,
                         dirpath,
                         result,
                         dirent_count,
                         offset,
                         result_count,
                         directory_size)) {
        nexus_free(dirpath);
        nexus_free(result);
        return NULL;
    }

    nexus_free(dirpath);

    return result;
}

int
nexus_fuse_stat(struct my_dentry * dentry, struct nexus_stat * stat)
{
    char * dirpath = NULL;


    if (dentry->ino == FUSE_ROOT_ID) {
        return nexus_fs_stat(nexus_fuse_volume, "/", stat);
    }


    dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_stat(nexus_fuse_volume, dirpath, stat)) {
        nexus_free(dirpath);
        return -1;
    }

    nexus_free(dirpath);

    return 0;
}

int
nexus_fuse_getattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs)
{
    char * path = NULL;


    if (dentry->ino == FUSE_ROOT_ID) {
        return nexus_fs_getattr(nexus_fuse_volume, "/", attrs);
    }


    path = dentry_get_fullpath(dentry);

    if (path == NULL) {
        return -1;
    }

    if (nexus_fs_getattr(nexus_fuse_volume, path, attrs)) {
        nexus_free(path);
        return -1;
    }

    // update the inode number
    attrs->posix_stat.st_ino = nexus_uuid_hash(&attrs->stat_info.uuid);

    nexus_free(path);

    return 0;
}


int
nexus_fuse_setattr(struct my_dentry * dentry, struct nexus_fs_attr * attrs, int to_set)
{
    char * dirpath = NULL;

    nexus_fs_attr_flags_t flags = to_set; // the to_set flags and nexus flags are the same


    if (dentry->ino == FUSE_ROOT_ID) {
        return nexus_fs_setattr(nexus_fuse_volume, "/", attrs, flags);
    }


    dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_setattr(nexus_fuse_volume, dirpath, attrs, flags)) {
        nexus_free(dirpath);
        return -1;
    }

    // update the inode number
    attrs->posix_stat.st_ino = nexus_uuid_hash(&attrs->stat_info.uuid);

    nexus_free(dirpath);

    return 0;
}

int
nexus_fuse_lookup(struct my_dentry * dentry, char * filename, struct nexus_fs_lookup * lookup_info)
{
    char * dirpath = dentry_get_fullpath(dentry);

    if (dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_lookup(nexus_fuse_volume, dirpath, filename, lookup_info)) {
        nexus_free(dirpath);
        return -1;
    }

    nexus_free(dirpath);

    return 0;
}

int
nexus_fuse_touch(struct my_dentry  * dentry,
                 char              * filename,
                 nexus_dirent_type_t type,
                 struct nexus_stat * nexus_stat)
{
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_touch(nexus_fuse_volume, parent_dirpath, filename, type, &nexus_stat->uuid)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    // setup the stat info
    nexus_stat->type = type;
    nexus_stat->size = 0;

    nexus_free(parent_dirpath);

    return 0;
}

int
nexus_fuse_remove(struct my_dentry * dentry, char * filename, fuse_ino_t * ino)
{
    struct nexus_uuid uuid;
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_remove(nexus_fuse_volume, parent_dirpath, filename, &uuid)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    *ino = nexus_uuid_hash(&uuid);

    nexus_free(parent_dirpath);

    return 0;
}

int
nexus_fuse_readlink(struct my_dentry * dentry, char ** target)
{
    char * parent_dirpath = dentry_get_parent_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    int ret = nexus_fs_readlink(nexus_fuse_volume, parent_dirpath, dentry->name, target);

    nexus_free(parent_dirpath);

    return ret;
}

int
nexus_fuse_symlink(struct my_dentry  * dentry,
                   char              * name,
                   char              * target,
                   struct nexus_stat * stat_info)
{
    char * parent_dirpath = dentry_get_fullpath(dentry);

    if (parent_dirpath == NULL) {
        return -1;
    }

    if (nexus_fs_symlink(nexus_fuse_volume, parent_dirpath, name, target, stat_info)) {
        nexus_free(parent_dirpath);
        return -1;
    }

    stat_info->type = NEXUS_LNK;

    nexus_free(parent_dirpath);

    return 0;
}
