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

static char *
print_rights(acl_rights_t rights);

int
dirops_new1(const char * parent_dir,
            const char * fname,
            ucafs_entry_type type,
            char ** shadow_name_dest)
{
    int error = -1; // TODO change this
    dentry_t * dentry = NULL;
    uc_dirnode_t * dirnode = NULL;
    uc_filebox_t * filebox = NULL;
    shadow_t * fname_code = NULL;
    sds path1 = NULL;

    /* lets get the dentry */
    if ((dentry = dentry_lookup(parent_dir, DIROPS_CREATE)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        return error;
    }

    if ((dirnode = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        goto out;
    }

    /* check if they have the rights */
    if (dirnode_checkacl(dirnode, ACCESS_INSERT)) {
        char * acl_str = print_rights(ACCESS_INSERT);
        log_error("[check_acl] %s ~> %s", parent_dir, acl_str);
        free(acl_str);
        goto out;
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
    if (path1)
        sdsfree(path1);
    if (fname_code)
        free(fname_code);

    d_put(dentry);

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
dirops_code2plain(const char * parent_dir,
                  const char * encoded_name,
                  ucafs_entry_type type,
                  char ** raw_name_dest)
{
    int error = -1; // TODO
    shadow_t * fname_code = NULL;
    ucafs_entry_type atype;
    const char * result;
    dentry_t * dentry;
    uc_dirnode_t * dn;
    char * acl_str = NULL;

    /* lets get the dentry */
    if ((dentry = dentry_lookup(parent_dir, DIROPS_LOOKUP)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        return error;
    }

    /* 1 - Get the binary version */
    if ((fname_code = filename_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    if ((dn = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        goto out;
    }

    /* check if they have the rights */
    if (dirnode_checkacl(dn, ACCESS_LOOKUP)) {
        char * acl_str = print_rights(ACCESS_LOOKUP);
        log_error("[check_acl] %s ~> %s", parent_dir, acl_str);
        free(acl_str);
        goto out;
    }

    // 3 - Get the plain filename
    if ((result = dirnode_enc2raw(dn, fname_code, UC_ANY, &atype)) == NULL) {
        goto out;
    }

    *raw_name_dest = strdup(result);
    error = 0;
out:
    if (fname_code) {
        free(fname_code);
    }

    d_put(dentry);
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
    int error = UC_STATUS_NOOP, jrnl1, jrnl2;
    ucafs_entry_type atype;
    uc_dirnode_t *dirnode1 = NULL, *dirnode2 = NULL, *dirnode3 = NULL;
    link_info_t *link_info1 = NULL, *link_info2 = NULL;
    shadow_t *shadow1_bin = NULL, *shadow2_bin = NULL;
    char *shadow1_str = NULL, *shadow2_str = NULL;
    sds fpath1 = NULL, fpath2 = NULL, dpath1 = NULL, dpath2 = NULL;
    dentry_t * dentry1, * dentry2;

    /* get the dentries */
    if ((dentry1 = dentry_lookup(from_dir, DIROPS_MOVE)) == NULL) {
        log_error("dentry_lookup: %s", from_dir);
        return error;
    }

    if ((dentry2 = dentry_lookup(to_dir, DIROPS_MOVE)) == NULL) {
        log_error("dentry_lookup: %s", to_dir);
        d_put(dentry1);
        return error;
    }

    /* XXX this is extremely innefficient. If they share the same dirnode,
     * just a rename should work */
    d_remove(dentry1, oldname);
    d_remove(dentry2, newname);

    if ((dirnode1 = d_dirnode(dentry1)) == NULL) {
        log_error("d_dirnode NULL: %s", from_dir);
        goto out;
    }

    if ((dirnode2 = d_dirnode(dentry2)) == NULL) {
        log_error("d_dirnode NULL: %s", to_dir);
        goto out;
    }

    /* check access control */
    if (dirnode_checkacl(dirnode1, ACCESS_DELETE)) {
        char * acl_str = print_rights(ACCESS_DELETE);
        log_error("[check_acl] %s ~> %s", from_dir, acl_str);
        free(acl_str);
        goto out;
    }

    if (dirnode_checkacl(dirnode2, ACCESS_INSERT)) {
        char * acl_str = print_rights(ACCESS_INSERT);
        log_error("[check_acl] %s ~> %s", to_dir, acl_str);
        free(acl_str);
        goto out;
    }

    if (dirnode1 == dirnode2 || dirnode_equals(dirnode1, dirnode2)) {
        if (dirnode_rename(dirnode1, oldname, newname, type, &atype,
                           &shadow1_bin, &shadow2_bin, &link_info1,
                           &link_info2, &jrnl1, &jrnl2)) {
            log_error("rename (%s) %s -> %s FAILED", from_dir, oldname,
                      newname);
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
            = dirnode_rm(dirnode1, oldname, type, &atype, &jrnl1, &link_info1);
        if (shadow1_bin == NULL) {
            log_error("finding '%s' failed", oldname);
            goto out;
        }

        // the new file might still exist in the dirnode
        dirnode_rm(dirnode2, newname, UC_ANY, &atype, &jrnl2, &link_info2);
        shadow2_bin = dirnode_add_alias(dirnode2, newname, atype, jrnl2,
                                        shadow1_bin, link_info1);
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

    if (atype == UC_LINK) {
        goto skip_moving_metadata;
    }

    /* now delete the structures on disk */
    fpath1 = metadata_afsx_path(dirnode1, shadow1_bin,
                                (atype == UC_DIR ? &dpath1 : NULL));
    fpath2 = metadata_afsx_path(dirnode2, shadow2_bin,
                                (atype == UC_DIR ? &dpath2 : NULL));

    /* move the metadata file */
    if (jrnl1 == JRNL_NOOP) {
        if (rename(fpath1, fpath2)) {
            log_error("renaming metadata file failed");
            goto out;
        }

        /* last step is to update the moved entry's parent directory. */
        if (atype == UC_DIR) {
            if (rename(dpath1, dpath2)) {
                log_error("renaming metadata file failed");
                goto out;
            }

            if ((dirnode3 = dirnode_from_file(fpath2)) == NULL) {
                log_info("loading dirnode file failed(%s)", fpath2);
                goto out;
            }

            dirnode_set_parent(dirnode3, dirnode2);

            if (!dirnode_flush(dirnode3)) {
                log_error("flushing dirnode (%s) failed", fpath2);
                goto out;
            }
        }
    }

skip_moving_metadata:
    // XXX what about the linking info.
    // For softlinks, since no on-disk structures are touched, we are fine
    // For hardlinks, we should be good as well as they still point to the file
    shadow1_str = filename_bin2str(shadow1_bin);
    shadow2_str = filename_bin2str(shadow2_bin);
    if (shadow1_str == NULL || shadow2_str == NULL) {
        log_error("converting shadowname to str");
        goto out;
    }

    *ptr_oldname = shadow1_str;
    *ptr_newname = shadow2_str;

    error = 0;
out:
    d_put(dentry1);
    d_put(dentry2);

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

    if (fpath1) {
        sdsfree(fpath1);
    }

    if (fpath2) {
        sdsfree(fpath2);
    }

    if (dpath1) {
        sdsfree(dpath1);
    }

    if (dpath2) {
        sdsfree(dpath2);
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
    dentry_t * dentry;

    /* 1 - get the respective dirnode */
    if ((dentry = dentry_lookup(link_path, DIROPS_SYMLINK)) == NULL) {
        log_error("dentry_lookup: %s", link_path);
        return error;
    }

    if ((link_dnode = d_dirnode(dentry)) == NULL) {
        log_error("dirnode (%s) not found", link_path);
        goto out;
    }

    /* check if we can insert into the DIRNODE */
    if (dirnode_checkacl(link_dnode, ACCESS_INSERT)) {
        char * acl_str = print_rights(ACCESS_INSERT);
        log_error("[check_acl] %s ~> %s", link_path, acl_str);
        free(acl_str);
        goto out;
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
    int error = UC_STATUS_NOOP;
    uc_dirnode_t *link_dnode = NULL;
    sds target_fname = NULL, link_fname = NULL, target_afsx_path = NULL,
        link_afsx_path = NULL;
    shadow_t * shadow_name2 = NULL;
    ucafs_entry_type atype;
    dentry_t * dentry1, *dentry2;
    uc_filebox_t * filebox = NULL;

    filebox = dcache_filebox(target_path, 0, UCAFS_STORE);
    if (filebox == NULL) {
        log_error("finding filebox failed: '%s'", target_path);
        return -1;
    }

    if ((dentry2 = dentry_lookup(link_path, DIROPS_HARDLINK)) == NULL) {
        log_error("dentry_lookup %s", link_path);
        d_put(dentry1);
        return error;
    }

    /* 1 - Get the dirnodes for both link and target */
    if ((link_dnode = d_dirnode(dentry2)) == NULL) {
        log_error("dirnode (%s) not found", link_path);
        return error;
    }

    /* Hardlink the files on the hardisk */
    if ((target_fname = do_get_fname(target_path)) == NULL) {
        log_error("getting fname (%s) FAILED", target_path);
        goto out;
    }

    if ((link_fname = do_get_fname(link_path)) == NULL) {
        log_error("getting fname (%s) FAILED", link_path);
        goto out;
    }

    /* check if we can insert into the DIRNODE */
    if (dirnode_checkacl(link_dnode, ACCESS_INSERT)) {
        char * acl_str = print_rights(ACCESS_INSERT);
        log_error("[check_acl] %s ~> %s", link_path, acl_str);
        free(acl_str);
        goto out;
    }

    /* get the shadow name of the target file */
    shadow_name2 = dirnode_add(link_dnode, link_fname, UC_FILE, JRNL_NOOP);
    if (shadow_name2 == NULL) {
        log_error("adding link (%s) FAILED", link_path);
        goto out;
    }

    /* get the metadata file */
    target_afsx_path = filebox_get_path(filebox);
    link_afsx_path = vfs_metadata_fpath(link_dnode, shadow_name2);

    if (link(target_afsx_path, link_afsx_path)) {
        log_error("hardlink '%s' -> '%s' FAILED", target_afsx_path,
                  link_afsx_path);
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
    d_put(dentry1);
    d_put(dentry2);

    if (target_fname) {
        sdsfree(target_fname);
    }

    if (link_fname) {
        sdsfree(link_fname);
    }

    if (target_afsx_path) {
        sdsfree(target_afsx_path);
    }

    if (link_afsx_path) {
        sdsfree(link_afsx_path);
    }

    if (shadow_name2) {
        free(shadow_name2);
    }

    if (filebox) {
        filebox_free(filebox);
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
dirops_plain2code1(const char * parent_dir,
                   const char * fname,
                   ucafs_entry_type type,
                   char ** encoded_fname_dest)
{
    int error = -1; // TODO
    const shadow_t * fname_code = NULL;
    ucafs_entry_type atype;
    dentry_t * dentry;
    uc_dirnode_t * dirnode;
    char * acl_str = NULL;

    /* lets get the dentry */
    if ((dentry = dentry_lookup(parent_dir, DIROPS_LOOKUP)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        return error;
    }

    if ((dirnode = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        goto out;
    }

    /* check if they have the rights */
    if (dirnode_checkacl(dirnode, ACCESS_LOOKUP)) {
        char * acl_str = print_rights(ACCESS_LOOKUP);
        log_error("[check_acl] %s ~> %s", parent_dir, acl_str);
        free(acl_str);
        goto out;
    }

    /* Perform the operation */
    fname_code = dirnode_raw2enc(dirnode, fname, type, &atype);
    if (fname_code == NULL) {
        //log_warn("%s not found (%s)", fname, parent_dir);
        goto out;
    }

    *encoded_fname_dest = filename_bin2str(fname_code);
    error = 0;
out:
    d_put(dentry);
    return error;
}

static int
__delete_metadata_file(sds metadata_filepath,
                       sds metadata_dirpath,
                       int is_filebox)
{
    int error = -1;
    uc_filebox_t * filebox = NULL;

    if (is_filebox) {
#if 0
        /* XXX: since we depend on the underlying filesystem to manage hardlinks,
         * this step seems to be unnecessary */

        /* instatiate, update ref count and delete */
        if ((filebox = filebox_from_file(metadata_filepath)) == NULL) {
            log_error("loading filebox (%s) FAILED", metadata_filepath);
            goto out;
        }

        if (filebox_decr_link_count(filebox)) {
            if (!filebox_flush(filebox)) {
                log_error("writing filebox (%s) FAILED", metadata_filepath);
                // goto out;
            }
        }
#endif

        /* delete the haardlink */
        if (unlink(metadata_filepath)) {
            log_error("deleting filebox (%s) FAILED", metadata_filepath);
            goto out;
        }
    } else {
        /* directories are a lot simpler. Since no hardlinks can't point to
         * directories, they only have one ref count. */
        if (rmdir(metadata_dirpath)) {
            log_warn("deleting dirnode (%s) FAILED", metadata_dirpath);
            goto out;
        }

        if (unlink(metadata_filepath)) {
            log_warn("deleting (%s) FAILED", metadata_filepath);
            goto out;
        }

        /* lazily remove the file entries */
        int x = 1;
        while (true) {
            sds path2 = string_and_number(metadata_filepath, x);

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
    dentry_t * dentry;
    uc_dirnode_t * dirnode = NULL;
    ucafs_entry_type atype;
    sds afsx_fpath = NULL, afsx_dpath = NULL;
    char * acl_str = NULL;

    if ((dentry = dentry_lookup(parent_dir, DIROPS_CHECKACL)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        return error;
    }

    /* remove it from the dentry cache */
    d_remove(dentry, fname);

    if ((dirnode = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", parent_dir);
        goto out;
    }

    if (dirnode_checkacl(dirnode, ACCESS_DELETE)) {
        char * acl_str = print_rights(ACCESS_DELETE);
        log_error("[check_acl] %s ~> %s", parent_dir, acl_str);
        free(acl_str);
        goto out;
    }

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

    /* ignore if it's a link or a "journal" file */
    if (atype != UC_LINK && jrnl == JRNL_NOOP) {
        afsx_fpath = metadata_afsx_path(dirnode, shadow_name,
                                        (atype == UC_DIR ? &afsx_dpath : NULL));
        __delete_metadata_file(afsx_fpath, afsx_dpath, atype == UC_FILE);
    }

    *encoded_fname_dest = filename_bin2str(shadow_name);
    error = 0;
out:
    d_put(dentry);

    if (shadow_name) {
        free(shadow_name);
    }

    if (link_info) {
        free(link_info);
    }

    if (afsx_fpath) {
        sdsfree(afsx_fpath);
    }

    if (afsx_dpath) {
        sdsfree(afsx_dpath);
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

static char *
print_rights(acl_rights_t rights)
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
    dentry_t * dentry;

    /* lets get the dentry */
    if ((dentry = dentry_lookup(path, DIROPS_CREATE)) == NULL) {
        log_error("Error loading dirnode: %s", path);
        return error;
    }

    if ((dirnode = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", path);
        goto out;
    }

    if (dirnode_checkacl(dirnode, ACCESS_ADMIN)) {
        char * acl_str = print_rights(ACCESS_ADMIN);
        log_error("[check_acl] %s ~> %s", path, acl_str);
        free(acl_str);
        goto out;
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
    d_put(dentry);

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
    dentry_t * dentry;

    // path could point to file or directory
    sds dirpath = is_dir ? (sds)path : do_get_dir(path);

    /* lets get the dentry */
    if ((dentry = dentry_lookup(dirpath, DIROPS_CHECKACL)) == NULL) {
        log_error("Error loading dirnode: %s", dirpath);
        return err;
    }

    if ((dirnode = d_dirnode(dentry)) == NULL) {
        log_error("Error loading dirnode: %s", dirpath);
        goto out;
    }

    if (dirnode_checkacl(dirnode, rights)) {
        log_error("[check_acl] %s ~> %s", path, (str = print_rights(rights)));
        goto out;
    }

    err = 0;
out:
    d_put(dentry);

    if (!is_dir) {
        sdsfree(dirpath);
    }

    if (str) {
        free(str);
    }

    return err;
}
