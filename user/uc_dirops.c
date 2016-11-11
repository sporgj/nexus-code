#include <string.h>

#include "third/slog.h"

#include "uc_dcache.h"
#include "uc_dirnode.h"
#include "uc_dirops.h"
#include "uc_encode.h"
#include "uc_filebox.h"
#include "uc_uspace.h"
#include "uc_utils.h"

int
dirops_new1(const char * parent_dir,
            const char * fname,
            ucafs_entry_type type,
            char ** shadow_name_dest)
{
    int error = -1; // TODO change this
    uc_dirnode_t *dirnode = NULL, *dirnode1 = NULL;
    uc_filebox_t * filebox = NULL;
    encoded_fname_t * fname_code = NULL;
    char * metaname = NULL;
    sds path1 = NULL;

    /* lets get the directory entry */
    if ((dirnode = dcache_get_dir(parent_dir)) == NULL) {
        slog(0, SLOG_ERROR, "Error loading dirnode: %s", parent_dir);
        return error;
    }

    /* Get filename and add it to DirNode */
    if ((fname_code = dirnode_add(dirnode, fname, type)) == NULL) {
        slog(0, SLOG_ERROR, "Add file operation failed: %s", parent_dir);
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "Flushing '%s' failed", parent_dir);
        goto out;
    }

    metaname = metaname_bin2str(fname_code);
    path1 = uc_get_dnode_path(metaname);

    if (type == UC_DIR) {
        if ((dirnode1 = dirnode_new()) == NULL) {
            slog(0, SLOG_ERROR, "new dirnode failed: %s/%s", parent_dir, fname);
            goto out;
        }

        dirnode_set_parent(dirnode1, dirnode);

        if (!dirnode_write(dirnode1, path1)) {
            slog(0, SLOG_ERROR, "Creating: '%s/%s' dirnode failed", parent_dir,
                 fname);
            goto out;
        }
    } else if (type == UC_FILE) {
        if ((filebox = filebox_new()) == NULL) {
            slog(0, SLOG_ERROR, "Creating '%s/%s' filebox failed", parent_dir,
                 fname);
            goto out;
        }

        if (!filebox_write(filebox, path1)) {
            slog(0, SLOG_ERROR, "Writing filebox to '%s' failed", path1);
            goto out;
        }
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
    if (dirnode1)
        dcache_put(dirnode1);
    if (path1)
        sdsfree(path1);
    if (fname_code)
        free((void *)fname_code);
    if (metaname)
        free(metaname);

    return error;
}

int
dirops_new(const char * fpath, ucafs_entry_type type, char ** encoded_name_dest)
{
    int error = -1;
    sds fname = NULL, dir_path = NULL;

    if ((fname = do_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Error getting file name: %s", fpath);
        return AFSX_STATUS_NOOP;
    }

    if ((dir_path = do_get_dir(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Error getting file name: %s", fpath);
        sdsfree(fname);
        return AFSX_STATUS_NOOP;
    }

    error = dirops_new1(dir_path, fname, type, encoded_name_dest);
out:
    sdsfree(fname);
    sdsfree(dir_path);
    return error;
}


int
dirops_code2plain(char * encoded_name,
                  char * dir_path,
                  ucafs_entry_type type,
                  char ** raw_name_dest)
{
    int error = -1; // TODO
    encoded_fname_t * fname_code = NULL;
    ucafs_entry_type atype;
    const char * result;

    /* 1 - Get the binary version */
    if ((fname_code = filename_str2bin(encoded_name)) == NULL) {
        return -1;
    }

    // 2 - Get the corresponding dirnode
    uc_dirnode_t * dn = dcache_get_dir(dir_path);
    if (dn == NULL) {
        goto out;
    }

    // 3 - Get the plain filename
    if ((result = dirnode_enc2raw(dn, fname_code, type, &atype)) == NULL) {
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

int
dirops_move(const char * from_dir,
            const char * oldname,
            const char * to_dir,
            const char * newname,
            ucafs_entry_type type,
            char ** ptr_oldname,
            char ** ptr_newname)
{
    int error = AFSX_STATUS_NOOP;
    ucafs_entry_type atype;
    uc_dirnode_t *dirnode1 = NULL, *dirnode2 = NULL, *dirnode3 = NULL;
    link_info_t *link_info1 = NULL, *link_info2 = NULL;
    encoded_fname_t *shadow1_bin = NULL, *shadow2_bin = NULL;
    char *shadow1_str = NULL, *shadow2_str = NULL, *metaname1 = NULL,
         *metaname2 = NULL;
    sds path1 = NULL, path2 = NULL, path3 = NULL;
    sds fpath1 = NULL, fpath2 = NULL;

    /* get the dirnode objects */
    dirnode1 = dcache_get_dir(from_dir);
    if (dirnode1 == NULL) {
        return -1;
    }

    dirnode2 = dcache_get_dir(to_dir);
    if (dirnode2 == NULL) {
        dcache_put(dirnode1);
        return -1;
    }

    // TODO remove entries from cache
    fpath1 = do_make_path(from_dir, oldname);
    fpath2 = do_make_path(to_dir, newname);

    dcache_rm(fpath1);
    dcache_rm(fpath2);

    sdsfree(fpath1);
    sdsfree(fpath2);

    if (dirnode_equals(dirnode1, dirnode2)) {
        if (dirnode_rename(dirnode1, oldname, newname, type, &atype, &shadow1_bin,
                           &shadow2_bin, &link_info1, &link_info2)) {
            slog(0, SLOG_ERROR, "dops_move - Could not rename (%s) %s -> %s",
                 from_dir, oldname, newname);
            goto out;
        }

        /* now write out the dirnode object */
        if (!dirnode_flush(dirnode1)) {
            slog(0, SLOG_ERROR, "dops_move - Could not flush dirnode (%s)",
                 from_dir);
            goto out;
        }
    } else {
        /* get the shadow names */
        shadow1_bin = dirnode_rm(dirnode1, oldname, type, &atype, &link_info1);
        if (shadow1_bin == NULL) {
            slog(0, SLOG_ERROR, "dirops_move - Could not find '%s' in dirnode",
                 oldname);
            goto out;
        }

        // the new file might still exist in the dirnode
        dirnode_rm(dirnode2, newname, UC_ANY, &atype, &link_info2);
        shadow2_bin
            = dirnode_add_alias(dirnode2, newname, atype, NULL, link_info1);
        if (shadow2_bin == NULL) {
            slog(0, SLOG_ERROR, "dops_move - Could not add '%s' to dirnode",
                 newname);
            goto out;
        }

        /* write the dirnode object */
        if (!dirnode_flush(dirnode1)) {
            slog(0, SLOG_ERROR, "dops_move - Could not flush dirnode (%s)",
                 from_dir);
            goto out;
        }

        if (!dirnode_flush(dirnode2)) {
            slog(0, SLOG_ERROR, "dops_move - Could not flush dirnode (%s)",
                 to_dir);
            goto out;
        }
    }

    /* now delete the structures on disk */
    shadow1_str = filename_bin2str(shadow1_bin);
    if (shadow1_str == NULL) {
        slog(0, SLOG_ERROR, "dops_move - Could not convert shadowname to str");
        goto out;
    }

    shadow2_str = filename_bin2str(shadow2_bin);
    if (shadow2_str == NULL) {
        slog(0, SLOG_ERROR, "dops_move - Could not convert shadowname to str");
        goto out;
    }

    metaname1 = metaname_bin2str(shadow1_bin);
    metaname2 = metaname_bin2str(shadow2_bin);
    path1 = uc_get_dnode_path(metaname1);
    path2 = uc_get_dnode_path(metaname2);

    /* move the metadata file */
    if (atype != UC_LINK) {
        if (rename(path1, path2)) {
            slog(0, SLOG_ERROR, "dops_move - renaming metadata file failed");
            goto out;
        }
    } else {
        slog(0, SLOG_INFO, "dops_move - renaming link (%s) %s -> %s", from_dir,
             oldname, newname);
    }

    /* update the parent directory */
    if (atype == UC_DIR) {
        path3 = uc_get_dnode_path(path2);
        if ((dirnode3 = dirnode_from_file(path3)) == NULL) {
            slog(0, SLOG_INFO, "loading dirnode file failed(%s)", path3);
            goto out;
        }

        dirnode_set_parent(dirnode3, dirnode2);

        if (!dirnode_flush(dirnode3)) {
            slog(0, SLOG_ERROR, "flushing dirnode (%s) failed", path3);
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

    if (dirnode3) {
        dirnode_free(dirnode3);
    }

    if (shadow1_bin) {
        free(shadow1_bin);
    }

    if (shadow2_bin) {
        free(shadow2_bin);
    }

    if (metaname1) {
        free(metaname1);
    }

    if (metaname2) {
        free(metaname2);
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
    int error = AFSX_STATUS_ERROR;
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
    int error = AFSX_STATUS_NOOP, len, link_info_len;
    link_info_t * link_info = NULL;
    uc_dirnode_t * link_dnode = NULL;
    encoded_fname_t * shadow_name2 = NULL;
    ucafs_entry_type atype;
    sds target_fname = NULL, link_fname = NULL;

    /* 1 - get the respective dirnode */
    if ((link_dnode = dcache_get(link_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode (%s) not found", link_path);
        return error;
    }

    /* 2 - Find the link to the file */
    if ((link_fname = do_get_fname(link_path)) == NULL) {
        slog(0, SLOG_ERROR, "getting fname (%s) FAILED", target_path);
        goto out;
    }

    /* 3 - create the link in the dnode */
    // for softlinks, we use the target path as it is resolved on
    // each access.
    len = strlen(target_path);
    link_info_len = len + sizeof(link_info_t) + 1;
    if ((link_info = (link_info_t *)calloc(1, link_info_len)) == NULL) {
        slog(0, SLOG_ERROR, "allocation failed for link_info");
        goto out;
    }

    link_info->total_len = link_info_len;
    link_info->type = UC_SOFTLINK;
    /* the meta file is useless */
    memcpy(&link_info->target_link, target_path, len);

    /* 5 - add it to the dirnode */
    shadow_name2 = dirnode_add_link(link_dnode, link_fname, link_info);
    if (shadow_name2 == NULL) {
        slog(0, SLOG_ERROR, "adding link (%s) FAILED", link_path);
        goto out;
    }

    if (!dirnode_flush(link_dnode)) {
        slog(0, SLOG_ERROR, "saving dirnode (%s) FAILED", link_path);
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

int
dirops_hardlink(const char * target_path,
                const char * link_path,
                char ** shadow_name_dest)
{
    int error = AFSX_STATUS_NOOP, len, link_info_len;
    char * fname = NULL;
    uc_filebox_t * target_fbox = NULL;
    uc_dirnode_t *target_dnode = NULL, *link_dnode = NULL;
    sds target_fname = NULL, link_fname = NULL;
    const encoded_fname_t * shadow_name1 = NULL;
    encoded_fname_t * shadow_name2 = NULL;
    ucafs_entry_type atype;
    link_info_t * link_info = NULL;

    /* 1 - Get the dirnodes for both link and target */
    if ((target_fbox = dcache_get_filebox(target_path)) == NULL) {
        slog(0, SLOG_ERROR, "filebox (%s) not found", target_path);
        return error;
    }

    if ((target_dnode = dcache_get(target_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode (%s) not found", target_path);
        filebox_free(target_fbox);
        return error;
    }

    if ((link_dnode = dcache_get(link_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode (%s) not found", link_path);
        filebox_free(target_fbox);
        dcache_put(target_dnode);
        return error;
    }

    /* 2 - get the filenames */
    if ((target_fname = do_get_fname(target_path)) == NULL) {
        slog(0, SLOG_ERROR, "getting fname (%s) FAILED", target_path);
        goto out;
    }

    if ((link_fname = do_get_fname(link_path)) == NULL) {
        slog(0, SLOG_ERROR, "getting fname (%s) FAILED", link_path);
        goto out;
    }

    /* 3 - get shadow name of the target */
    shadow_name1 = dirnode_raw2enc(target_dnode, target_fname, UC_ANY, &atype);
    if (shadow_name1 == NULL) {
        slog(0, SLOG_ERROR, "finding entry in (%s) FAILED", target_fname);
        goto out;
    }

    /* 4 - create the link in the dnode */
    len = sizeof(encoded_fname_t);
    link_info_len = len + sizeof(link_info_t) + 1;
    if ((link_info = (link_info_t *)calloc(1, link_info_len)) == NULL) {
        slog(0, SLOG_ERROR, "allocation failed for link_info");
        goto out;
    }

    link_info->total_len = link_info_len;
    link_info->type = UC_HARDLINK;
    memcpy(&link_info->meta_file, shadow_name1, sizeof(encoded_fname_t));

    /* 5 - add it to the dirnode */
    shadow_name2
        = dirnode_add_alias(link_dnode, link_fname, UC_FILE, NULL, link_info);
    if (shadow_name2 == NULL) {
        slog(0, SLOG_ERROR, "adding link (%s) FAILED", link_path);
        goto out;
    }

    filebox_incr_link_count(target_fbox);

    /* 6 - save the dirnodes */
    if (!filebox_flush(target_fbox)) {
        slog(0, SLOG_ERROR, "saving filebox (%s) FAILED", target_path);
        goto out;
    }

    if (!dirnode_flush(link_dnode)) {
        slog(0, SLOG_ERROR, "saving dirnode (%s) FAILED", link_path);
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
    int error = -1; // TODO
    sds fname = NULL;
    const encoded_fname_t * fname_code = NULL;
    ucafs_entry_type atype;
    sds dnode_path = NULL;

    /* 1 - Get the corresponding dirnode */
    uc_dirnode_t * dirnode = dcache_get(fpath_raw);
    if (dirnode == NULL) {
        return error;
    }

    if ((fname = do_get_fname(fpath_raw)) == NULL) {
        slog(0, SLOG_ERROR, "Could not get fname: %s", fpath_raw);
        goto out;
    }

    /* Perform the operation */
    fname_code = dirnode_raw2enc(dirnode, fname, type, &atype);
    if (fname_code == NULL) {
        slog(0, SLOG_WARN, "%s not found (%s)", fname, fpath_raw);
        goto out;
    }

    *encoded_fname_dest = filename_bin2str(fname_code);
    error = 0;
out:
    dcache_put(dirnode);
    if (fname)
        sdsfree(fname);
    if (dnode_path)
        sdsfree(dnode_path);
    return error;
}

static int
__delete_metadata_file(const encoded_fname_t * shadowname_bin, int is_filebox)
{
    int error = -1;
    uc_dirnode_t * dirnode = NULL;
    uc_filebox_t * filebox = NULL;
    sds metadata_path;

    char * metaname_str = metaname_bin2str(shadowname_bin);
    if (metaname_str == NULL) {
        return -1;
    }

    metadata_path = uc_get_dnode_path(metaname_str);
    if (metadata_path == NULL) {
        free(metaname_str);
        return -1;
    }

    if (is_filebox) {
        /* instatiate, update ref count and delete */
        if ((filebox = filebox_from_file(metadata_path)) == NULL) {
            slog(0, SLOG_ERROR, "loading filebox (%s) FAILED", metadata_path);
            goto out;
        }

        if (filebox_decr_link_count(filebox) == 0) {
            if (unlink(metadata_path)) {
                slog(0, SLOG_ERROR, "deleting filebox (%s) FAILED",
                     metadata_path);
                goto out;
            }
        } else {
            // write it to disk
            if (!filebox_flush(filebox)) {
                slog(0, SLOG_ERROR, "writing filebox (%s) FAILED",
                     metadata_path);
                goto out;
            }
        }
    } else {
        /* directories are a lot simpler. Since no hardlinks can't point to
         * directories,
         * they only have one ref count. */
        if (unlink(metadata_path)) {
            slog(0, SLOG_ERROR, "deleting dirnode (%s) FAILED", metadata_path);
            goto out;
        }
    }

    error = 0;
out:
    if (filebox) {
        filebox_free(filebox);
    }

    if (dirnode) {
        dirnode_free(dirnode);
    }

    if (metaname_str) {
        free(metaname_str);
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
    int error = AFSX_STATUS_ERROR;
    link_info_t * link_info = NULL;
    encoded_fname_t * shadow_name = NULL;
    uc_dirnode_t * dirnode = NULL;
    sds fname = NULL, path = NULL;
    ucafs_entry_type atype;

    if ((dirnode = dcache_get(fpath_raw)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode (%s) not found", fpath_raw);
        return error;
    }

    if ((fname = do_get_fname(fpath_raw)) == NULL) {
        slog(0, SLOG_ERROR, "getting fname (%s) failed", fpath_raw);
        goto out;
    }

    /* update the dcache */
    dcache_rm(fpath_raw);

    /* delete and get the info */
    shadow_name = dirnode_rm(dirnode, fname, type, &atype, &link_info);
    if (shadow_name == NULL) {
        slog(0, SLOG_ERROR, "shadow file (%s) not found", fname);
        goto out;
    }

    /* write the dirnode containing the file entry */
    if (!dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "flushing dirnode (%s) failed", fpath_raw);
        goto out;
    }

    /* we only need to call for hardlinks */
    if (link_info) {
        if (link_info->type == UC_HARDLINK) {
            __delete_metadata_file(&link_info->meta_file, 1);
        }
    } else {
        // delete a normal file or directory
        __delete_metadata_file(shadow_name, atype == UC_FILE);
    }

    *encoded_fname_dest = filename_bin2str(shadow_name);
    error = 0;
out:
    dcache_put(dirnode);

    if (fname) {
        sdsfree(fname);
    }

    if (path) {
        sdsfree(path);
    }

    if (shadow_name) {
        free(shadow_name);
    }

    if (link_info) {
        free(link_info);
    }

    return error;
}
