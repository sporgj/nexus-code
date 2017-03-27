#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "third/log.h"

#include "uc_dirnode.h"
#include "uc_dirops.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_uspace.h"
#include "uc_utils.h"
#include "uc_vfs.h"

int
dirops_new1(const char * parent_dir,
            const char * fname,
            ucafs_entry_type type,
            char ** shadow_name_dest)
{
    int error = -1; // TODO change this
    uc_dirnode_t *dirnode = NULL;
    uc_filebox_t * filebox = NULL;
    shadow_t * fname_code = NULL;
    sds path1 = NULL;

    /* lets get the directory entry */
    if ((dirnode = vfs_lookup(parent_dir, true)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        return error;
    }

    /* Get filename and add it to DirNode */
    if ((fname_code = dirnode_add(dirnode, fname, type, JRNL_CREATE)) == NULL) {
        log_error("Add file operation failed: %s", parent_dir);
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode_flush(dirnode)) {
        log_error("Flushing '%s' failed", parent_dir);
        goto out;
    }

    /* Set the encoded name */
    *shadow_name_dest = filename_bin2str(fname_code);
    error = 0;
out:
    /* TODO probably need to perform an additional check here concerning
     * failed dirnode/filebox writes to disk. */
    if (filebox)
        filebox_free(filebox);
    if (dirnode)
        dcache_put(dirnode);
    if (path1)
        sdsfree(path1);
    if (fname_code)
        free((void *)fname_code);

    return error;
}

int
dirops_new(const char * fpath, ucafs_entry_type type, char ** encoded_name_dest)
{
    int error = -1;
    sds fname = NULL, dir_path = NULL;

    if ((fname = do_get_fname(fpath)) == NULL) {
        log_error("Error getting file name: %s", fpath);
        return UC_STATUS_NOOP;
    }

    if ((dir_path = do_get_dir(fpath)) == NULL) {
        log_error("Error getting file name: %s", fpath);
        sdsfree(fname);
        return UC_STATUS_NOOP;
    }

    error = dirops_new1(dir_path, fname, type, encoded_name_dest);
out:
    sdsfree(fname);
    sdsfree(dir_path);
    return error;
}

int
dirops_code2plain(const char * dir_path,
                  const char * encoded_name,
                  ucafs_entry_type type,
                  char ** raw_name_dest)
{
    int error = -1; // TODO
    shadow_t * fname_code = NULL;
    ucafs_entry_type atype;
    const char * result;

    /* 1 - Get the binary version */
    if ((fname_code = filename_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    uc_dirnode_t * dn = vfs_lookup(dir_path, true);
    if (dn == NULL) {
        goto out;
    }

    // 3 - Get the plain filename
    if ((result = dirnode_enc2raw(dn, fname_code, UC_ANY, &atype)) == NULL) {
        goto out;
    }

    *raw_name_dest = strdup(result);
    error = 0;
out:
    if (fname_code)
        free(fname_code);
    if (dn)
        dcache_put(dn);
    return error;
}

// TODO for the journal entry
int
dirops_move(const char * from_dir,
            const char * oldname,
            const char * to_dir,
            const char * newname,
            ucafs_entry_type type,
            char ** ptr_oldname,
            char ** ptr_newname)
{
    int error = UC_STATUS_NOOP, jrnl;
    ucafs_entry_type atype;
    uc_dirnode_t *dirnode1 = NULL, *dirnode2 = NULL, *dirnode3 = NULL;
    link_info_t *link_info1 = NULL, *link_info2 = NULL;
    shadow_t *shadow1_bin = NULL, *shadow2_bin = NULL;
    char *shadow1_str = NULL, *shadow2_str = NULL;
    sds path1 = NULL, path2 = NULL, path3 = NULL;
    sds fpath1 = NULL, fpath2 = NULL;

    /* get the dirnode objects */
    dirnode1 = vfs_lookup(from_dir, true);
    if (dirnode1 == NULL) {
        return -1;
    }

    dirnode2 = vfs_lookup(to_dir, true);
    if (dirnode2 == NULL) {
        dcache_put(dirnode1);
        return -1;
    }

    // XXX future versions should check if the entries are
    // directories before removing them
    dcache_rm(dirnode1, oldname);
    dcache_rm(dirnode2, newname);

    if (dirnode_equals(dirnode1, dirnode2)) {
        if (dirnode_rename(dirnode1, oldname, newname, type, &atype,
                           &shadow1_bin, &shadow2_bin, &link_info1,
                           &link_info2)) {
            log_error("rename (%s) %s -> %s FAILED", from_dir,
                 oldname, newname);
            goto out;
        }

        /* now write out the dirnode object */
        if (!dirnode_flush(dirnode1)) {
            log_error("flushing dirnode (%s) FAILED", from_dir);
            goto out;
        }
    } else {
        /* get the shadow names */
        shadow1_bin
            = dirnode_rm(dirnode1, oldname, type, &atype, &jrnl, &link_info1);
        if (shadow1_bin == NULL) {
            log_error("finding '%s' failed", oldname);
            goto out;
        }

        // the new file might still exist in the dirnode
        dirnode_rm(dirnode2, newname, UC_ANY, &atype, &jrnl, &link_info2);
        shadow2_bin = dirnode_add_alias(dirnode2, newname, atype, jrnl, NULL,
                                        link_info1);
        if (shadow2_bin == NULL) {
            log_error("adding '%s' to dirnode FAILED", newname);
            goto out;
        }

        /* write the dirnode object */
        if (!dirnode_flush(dirnode1)) {
            log_error("flushing dirnode (%s) FAILED", from_dir);
            goto out;
        }

        if (!dirnode_flush(dirnode2)) {
            log_error("flushing dirnode (%s)", to_dir);
            goto out;
        }
    }

    /* now delete the structures on disk */
    shadow1_str = filename_bin2str(shadow1_bin);
    shadow2_str = filename_bin2str(shadow2_bin);
    if (shadow1_str == NULL || shadow2_str == NULL) {
        log_error("converting shadowname to str");
        goto out;
    }

    path1 = vfs_metadata_path(from_dir, shadow1_bin);
    path2 = vfs_metadata_path(to_dir, shadow2_bin);

    // TODO just update the entry in the dirnode
    /* move the metadata file */
    if (atype != UC_LINK) {
        if (rename(path1, path2)) {
            log_error("renaming metadata file failed");
            goto out;
        }
    } else {
        log_info("renaming link (%s) %s -> %s", from_dir, oldname, newname);
    }

    /* last step is to update the moved entry's parent directory. */
    if (atype == UC_DIR) {
        if ((dirnode3 = dirnode_from_file(path2)) == NULL) {
            log_info("loading dirnode file failed(%s)", path3);
            goto out;
        }

        dirnode_set_parent(dirnode3, dirnode2);

        if (!dirnode_flush(dirnode3)) {
            log_error("flushing dirnode (%s) failed", path3);
            goto out;
        }
    }

    // XXX what about the linking info.
    // For softlinks, since no on-disk structures are touched, we are fine
    // For hardlinks, we should be good as well as they still point to the file

    *ptr_oldname = shadow1_str;
    *ptr_newname = shadow2_str;

    error = 0;
out:
    dcache_put(dirnode1);
    dcache_put(dirnode2);

    if (shadow1_bin) {
        free(shadow1_bin);
    }

    if (shadow2_bin) {
        free(shadow2_bin);
    }

    if (error && shadow1_str) {
        free(shadow1_str);
    }

    if (error && shadow2_str) {
        free(shadow2_str);
    }

    if (path1) {
        sdsfree(path1);
    }

    if (path2) {
        sdsfree(path2);
    }

    return error;
}

int
dirops_move1(const char * from_fpath,
             const char * to_fpath,
             ucafs_entry_type type,
             char ** ptr_oldname,
             char ** ptr_newname)
{
    int error = UC_STATUS_ERROR;
    sds fname1 = NULL, fname2 = NULL, path1 = NULL, path2 = NULL;

    if ((fname1 = do_get_fname(from_fpath)) == NULL) {
        goto out;
    }

    if ((fname2 = do_get_fname(to_fpath)) == NULL) {
        goto out;
    }

    if ((path1 = do_get_dir(from_fpath)) == NULL) {
        goto out;
    }

    if ((path2 = do_get_dir(to_fpath)) == NULL) {
        goto out;
    }

    error = dirops_move(path1, fname1, path2, fname2, type, ptr_oldname,
                        ptr_newname);
out:
    if (fname1)
        sdsfree(fname1);
    if (fname2)
        sdsfree(fname2);
    if (path1)
        sdsfree(path1);
    if (path2)
        sdsfree(path2);

    return error;
}

int
dirops_symlink(const char * link_path,
               const char * target_path,
               char ** shadow_name_dest)
{
    int error = UC_STATUS_NOOP, len, link_info_len;
    link_info_t * link_info = NULL;
    uc_dirnode_t * link_dnode = NULL;
    shadow_t * shadow_name2 = NULL;
    ucafs_entry_type atype;
    sds target_fname = NULL, link_fname = NULL;

    /* 1 - get the respective dirnode */
    if ((link_dnode = vfs_lookup(link_path, false)) == NULL) {
        log_error("dirnode (%s) not found", link_path);
        return error;
    }

    /* 2 - Find the link to the file */
    if ((link_fname = do_get_fname(link_path)) == NULL) {
        log_error("getting fname (%s) FAILED", target_path);
        goto out;
    }

    /* 3 - create the link in the dnode */
    // for softlinks, we use the target path as it is resolved on
    // each access.
    len = strlen(target_path);
    link_info_len = len + sizeof(link_info_t) + 1;
    if ((link_info = (link_info_t *)calloc(1, link_info_len)) == NULL) {
        log_error("allocation failed for link_info");
        goto out;
    }

    link_info->total_len = link_info_len;
    link_info->type = UC_SOFTLINK;
    /* the meta file is useless */
    memcpy(&link_info->target_link, target_path, len);

    /* 5 - add it to the dirnode */
    shadow_name2 = dirnode_add_link(link_dnode, link_fname, link_info);
    if (shadow_name2 == NULL) {
        log_error("adding link (%s) FAILED", link_path);
        goto out;
    }

    if (!dirnode_flush(link_dnode)) {
        log_error("saving dirnode (%s) FAILED", link_path);
        goto out;
    }

    /* 7 - return the whole thing */
    *shadow_name_dest = filename_bin2str(shadow_name2);
    error = 0;
out:
    dcache_put(link_dnode);

    if (target_fname) {
        sdsfree(target_fname);
    }

    if (link_info) {
        free(link_info);
    }

    if (shadow_name2) {
        free(shadow_name2);
    }

    if (link_fname) {
        sdsfree(link_fname);
    }

    return error;
}

// TODO for the journal entry
int
dirops_hardlink(const char * target_path,
                const char * link_path,
                char ** shadow_name_dest)
{
    int error = UC_STATUS_NOOP, len, link_info_len;
    char * fname = NULL;
    uc_filebox_t * target_fbox = NULL;
    uc_dirnode_t *target_dnode = NULL, *link_dnode = NULL;
    sds target_fname = NULL, link_fname = NULL;
    const shadow_t * shadow_name1 = NULL;
    shadow_t * shadow_name2 = NULL;
    ucafs_entry_type atype;
    link_info_t * link_info = NULL;

    /* 1 - Get the dirnodes for both link and target */
    if ((target_fbox = vfs_get_filebox(target_path, 0)) == NULL) {
        log_error("filebox (%s) not found", target_path);
        return error;
    }

    if ((target_dnode = vfs_lookup(target_path, false)) == NULL) {
        log_error("dirnode (%s) not found", target_path);
        filebox_free(target_fbox);
        return error;
    }

    if ((link_dnode = vfs_lookup(link_path, false)) == NULL) {
        log_error("dirnode (%s) not found", link_path);
        filebox_free(target_fbox);
        dcache_put(target_dnode);
        return error;
    }

    /* 2 - get the filenames */
    if ((target_fname = do_get_fname(target_path)) == NULL) {
        log_error("getting fname (%s) FAILED", target_path);
        goto out;
    }

    if ((link_fname = do_get_fname(link_path)) == NULL) {
        log_error("getting fname (%s) FAILED", link_path);
        goto out;
    }

    /* 3 - get shadow name of the target */
    shadow_name1 = dirnode_raw2enc(target_dnode, target_fname, UC_ANY, &atype);
    if (shadow_name1 == NULL) {
        log_error("finding entry in (%s) FAILED", target_fname);
        goto out;
    }

    /* 4 - create the link in the dnode */
    len = sizeof(shadow_t);
    link_info_len = len + sizeof(link_info_t) + 1;
    if ((link_info = (link_info_t *)calloc(1, link_info_len)) == NULL) {
        log_error("allocation failed for link_info");
        goto out;
    }

    link_info->total_len = link_info_len;
    link_info->type = UC_HARDLINK;
    memcpy(&link_info->meta_file, shadow_name1, sizeof(shadow_t));

    /* 5 - add it to the dirnode */
    /* to hardlink, there must be an existing on-disk filebox */
    shadow_name2 = dirnode_add_alias(link_dnode, link_fname, UC_FILE, JRNL_NOOP,
                                     NULL, link_info);
    if (shadow_name2 == NULL) {
        log_error("adding link (%s) FAILED", link_path);
        goto out;
    }

    filebox_incr_link_count(target_fbox);

    /* 6 - save the dirnodes */
    if (!filebox_flush(target_fbox)) {
        log_error("saving filebox (%s) FAILED", target_path);
        goto out;
    }

    if (!dirnode_flush(link_dnode)) {
        log_error("saving dirnode (%s) FAILED", link_path);
        goto out;
    }

    /* 7 - return the whole thing */
    *shadow_name_dest = filename_bin2str(shadow_name2);
    error = 0;
out:
    filebox_free(target_fbox);
    dcache_put(target_dnode);
    dcache_put(link_dnode);

    if (target_fname) {
        sdsfree(target_fname);
    }

    if (link_fname) {
        sdsfree(link_fname);
    }

    if (link_info) {
        free(link_info);
    }

    if (shadow_name2) {
        free(shadow_name2);
    }

    return error;
}

int
dirops_plain2code(const char * fpath_raw,
                  ucafs_entry_type type,
                  char ** encoded_fname_dest)
{
    int ret;
    sds fname, dir_path;

    if ((fname = do_get_fname(fpath_raw)) == NULL) {
        log_error("Error getting file name: %s", fpath_raw);
        return UC_STATUS_NOOP;
    }

    if ((dir_path = do_get_dir(fpath_raw)) == NULL) {
        log_error("Error getting file name: %s", fpath_raw);
        sdsfree(fname);
        return UC_STATUS_NOOP;
    }

    ret = dirops_plain2code1(dir_path, fname, type, encoded_fname_dest);

    sdsfree(fname);
    sdsfree(dir_path);
    return ret;
}

int
dirops_plain2code1(const char * parent_path,
                   const char * fname,
                   ucafs_entry_type type,
                   char ** encoded_fname_dest)
{
    int error = -1; // TODO
    const shadow_t * fname_code = NULL;
    ucafs_entry_type atype;

    /* 1 - Get the corresponding dirnode */
    uc_dirnode_t * dirnode = vfs_lookup(parent_path, true);
    if (dirnode == NULL) {
        return error;
    }

    /* Perform the operation */
    fname_code = dirnode_raw2enc(dirnode, fname, type, &atype);
    if (fname_code == NULL) {
        log_warn("%s not found (%s)", fname, parent_path);
        goto out;
    }

    *encoded_fname_dest = filename_bin2str(fname_code);
    error = 0;
out:
    dcache_put(dirnode);
    return error;
}

static int
__delete_metadata_file(uc_dirnode_t * parent_dirnode,
                       const char * parent_dir,
                       const shadow_t * shadowname_bin,
                       int jrnl,
                       int is_filebox)
{
    int error = -1;
    uc_filebox_t * filebox = NULL;
    sds metadata_path = NULL;

    /* check if the entry is in the journal */
    if (jrnl != JRNL_NOOP) {
        /* then we know there's no on-disk metadata file */
        return 0;
    }

    metadata_path = vfs_metadata_path(parent_dir, shadowname_bin);
    if (is_filebox) {
        /* instatiate, update ref count and delete */
        if ((filebox = filebox_from_file(metadata_path)) == NULL) {
            log_error("loading filebox (%s) FAILED", metadata_path);
            goto out;
        }

        if (filebox_decr_link_count(filebox) == 0) {
            if (unlink(metadata_path)) {
                log_error("deleting filebox (%s) FAILED",
                     metadata_path);
                goto out;
            }
        } else {
            // write it to disk
            if (!filebox_flush(filebox)) {
                log_error("writing filebox (%s) FAILED",
                     metadata_path);
                goto out;
            }
        }
    } else {
        /* directories are a lot simpler. Since no hardlinks can't point to
         * directories, they only have one ref count. */
        if (unlink(metadata_path)) {
            log_error("deleting dirnode (%s) FAILED", metadata_path);
            goto out;
        }

        /* lazily remove the file entries */
        int x = 1;
        while(true) {
            sds path2 = string_and_number(metadata_path, x);

            if (unlink(path2)) {
                // log_warn("deleting split (%s) FAILED", path2);
                sdsfree(path2);
                break;
            }

            sdsfree(path2);
            x++;
        }
    }

    error = 0;
out:
    if (filebox) {
        filebox_free(filebox);
    }

    if (metadata_path) {
        sdsfree(metadata_path);
    }

    return error;
}

int
dirops_remove(const char * fpath_raw,
              ucafs_entry_type type,
              char ** encoded_fname_dest)
{
    int error = -1;
    sds fname = NULL, dir_path = NULL;

    if ((fname = do_get_fname(fpath_raw)) == NULL) {
        log_error("Error getting file name: %s", fpath_raw);
        return UC_STATUS_NOOP;
    }

    if ((dir_path = do_get_dir(fpath_raw)) == NULL) {
        log_error("Error getting file name: %s", fpath_raw);
        sdsfree(fname);
        return UC_STATUS_NOOP;
    }

    error = dirops_remove1(dir_path, fname, type, encoded_fname_dest);

    sdsfree(fname);
    sdsfree(dir_path);
    return error;
}

int
dirops_remove1(const char * parent_dir,
               const char * fname,
               ucafs_entry_type type,
               char ** encoded_fname_dest)
{
    int error = UC_STATUS_ERROR, jrnl;
    link_info_t * link_info = NULL;
    shadow_t * shadow_name = NULL;
    uc_dirnode_t * dirnode = NULL;
    ucafs_entry_type atype;

    if ((dirnode = vfs_lookup(parent_dir, true)) == NULL) {
        log_error("dirnode (%s) not found", parent_dir);
        return error;
    }

    /* update the dcache */
    dcache_rm(dirnode, fname);

    /* delete and get the info */
    shadow_name = dirnode_rm(dirnode, fname, type, &atype, &jrnl, &link_info);
    if (shadow_name == NULL) {
        log_error("shadow file (%s) not found", fname);
        goto out;
    }

    /* write the dirnode containing the file entry */
    if (!dirnode_flush(dirnode)) {
        log_error("flushing dirnode (%s) failed", parent_dir);
        goto out;
    }

    /* if it's a directory, remove it from the metadata cache */
    if (atype == UC_DIR) {
        metadata_rm_dirnode(shadow_name);
    }

    /* we only need to call for hardlinks */
    if (link_info) {
        if (link_info->type == UC_HARDLINK) {
            __delete_metadata_file(dirnode, parent_dir, &link_info->meta_file,
                                   jrnl, 1);
        }
    } else {
        // delete a normal file or directory
        __delete_metadata_file(dirnode, parent_dir, shadow_name, jrnl,
                               atype == UC_FILE);
    }

    *encoded_fname_dest = filename_bin2str(shadow_name);
    error = 0;
out:
    dcache_put(dirnode);

    if (shadow_name) {
        free(shadow_name);
    }

    if (link_info) {
        free(link_info);
    }

    return error;
}

struct acl {
    int dfs;
    char cell[1025];
    int nplus;
    int nminus;
};

const char rights_str[] = "rwildka";

static char * print_rights(acl_rights_t rights)
{
    char * arr = calloc(1, sizeof(rights_str));
    size_t k = 1, l = 0;

    for (int i = 0; i < sizeof(rights_str) - 1; i++) {
        if (k & (size_t)rights) {
            arr[l++] = rights_str[i];
        }

        k <<= 1;
    }

    return arr;
}

static char *
skip_line(char * astr)
{
    while (*astr != '\n') {
        astr++;
    }

    return ++astr;
}

/**
 * Sets the acl in the dirnode structure
 */
int
dirops_setacl(const char * path, const char * afs_acl_str)
{
    int error = -1;
    uc_dirnode_t * dirnode = NULL;
    struct acl a, *ta = &a;
    char *astr = (char *)afs_acl_str, tname[CONFIG_MAX_NAME],
         *acl_print_str = NULL;
    acl_rights_t rights;

    if ((dirnode = vfs_lookup(path, true)) == NULL) {
        log_error("dirnode (%s) not found", path);
        return error;
    }

    ta->dfs = 0;
    sscanf(astr, "%d dfs:%d %1024s", &ta->nplus, &ta->dfs, ta->cell);
    astr = skip_line(astr);
    sscanf(astr, "%d", &ta->nminus);
    astr = skip_line(astr);

    /* clear the lockbox and start adding entries */
    dirnode_lockbox_clear(dirnode);

    for (int i = 0; i < ta->nplus; i++) {
        sscanf(astr, "%99s %d", tname, (int *)&rights);
        astr = skip_line(astr);

        // if there is a colon, it's a group
        if (strchr(tname, ':')) {
            continue;
        }

        if (dirnode_lockbox_add(dirnode, tname, rights)) {
            log_error("ACL (%s, %s) to dirnode (%s)", tname,
                      (acl_print_str = print_rights(rights)), path);
            goto out;
        }
    }

    if (!dirnode_flush(dirnode)) {
        log_error("flushing dirnode (%s) failed", path);
        goto out;
    }

    error = 0;
out:
    dcache_put(dirnode);

    if (acl_print_str) {
        free(acl_print_str);
    }

    return error;
}

int
dirops_checkacl(const char * path, acl_rights_t rights, int is_dir)
{
    int err = -1;
    uc_dirnode_t * dirnode = NULL;
    char * str = NULL;

    /* if it's a directory, get the dirnode it points to. Otherwise, for a file
     * get the parent dirnode */
    if ((dirnode = vfs_lookup(path, (is_dir ? true : false))) == NULL) {
        log_error("dirnode (%s) not found", path);
        return err;
    }

    if (dirnode_checkacl(dirnode, rights)) {
        log_error("[check_acl] %s ~> %s", path, (str = print_rights(rights)));
        goto out;
    }

    err = 0;
out:
    dcache_put(dirnode);

    free(str);

    return err;
}

