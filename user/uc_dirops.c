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
dirops_new(const char * fpath, ucafs_entry_type type, char ** encoded_name_dest)
{
    int error = -1; // TODO change this
    char *fname = do_get_fname(fpath), *temp;
    uc_dirnode_t *dirnode = NULL, *dirnode1 = NULL;
    uc_filebox_t * filebox = NULL;
    const encoded_fname_t * fname_code = NULL;
    sds path1 = NULL;

    if (fname == NULL) {
        slog(0, SLOG_ERROR, "Error getting file name: %s", fpath);
        goto out;
    }

    /* lets get the directory entry */
    if ((dirnode = dcache_get(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Error loading dirnode: %s", fpath);
        goto out;
    }

    /* Get filename and add it to DirNode */
    if ((fname_code = dirnode_add(dirnode, fname, type)) == NULL) {
        slog(0, SLOG_ERROR, "Add file operation failed: %s", fpath);
        goto out;
    }

    // 3 - Flush to disk
    if (!dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "Flushing '%s' failed", fpath);
        goto out;
    }

    temp = encode_bin2str(fname_code);
    path1 = uc_get_dnode_path(temp);

    if (type == UCAFS_TYPE_DIR) {
        if ((dirnode1 = dirnode_new()) == NULL) {
            slog(0, SLOG_ERROR, "new dirnode failed: %s", fpath);
            goto out;
        }

        if (!dirnode_write(dirnode1, path1)) {
            slog(0, SLOG_ERROR, "Creating: '%s' dirnode failed", fpath);
            goto out;
        }
    } else if (type == UCAFS_TYPE_FILE) {
        if ((filebox = filebox_new()) == NULL) {
            slog(0, SLOG_ERROR, "Creating '%s' filebox failed", fpath);
            goto out;
        }

        if (!filebox_write(filebox, path1)) {
            slog(0, SLOG_ERROR, "Writing filebox to '%s' failed", path1);
            goto out;
        }
    }

    /* Set the encoded name */
    *encoded_name_dest = temp;
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
    if (fname)
        sdsfree(fname);
    if (path1)
        sdsfree(path1);
    if (fname_code)
        free((void *)fname_code);

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
    if ((fname_code = encode_str2bin(encoded_name)) == NULL) {
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
dirops_rename2(const char * parent_path,
               const char * old_name,
               const char * new_name,
               ucafs_entry_type type,
               char ** encoded_name_dest)
{
    int error = AFSX_STATUS_NOOP;
    ucafs_entry_type atype;
    uc_dirnode_t * dirnode = NULL;
    const encoded_fname_t *codename1 = NULL, *codename2 = NULL;
    char *codename1_str = NULL, *codename2_str = NULL;
    sds path1 = NULL, path2 = NULL;
    sds oldname = sdsnew(old_name), newname = sdsnew(new_name);

    dirnode = dcache_get_dir(parent_path);
    if (dirnode == NULL) {
        return -1;
    }

    /* delete the old_name */
    codename1 = dirnode_rm(dirnode, oldname, type, &atype);
    if (codename1 == NULL) {
        slog(0, SLOG_ERROR, "dirops_rename - Removing '%s' from dirnode",
             oldname);
        goto out;
    }

    /* insert into the dirnode */
    type = (type == UCAFS_TYPE_LINK) ? UCAFS_TYPE_LINK : UCAFS_TYPE_FILE;

    codename2 = dirnode_add(dirnode, newname, type);
    if (codename2 == NULL) {
        slog(0, SLOG_ERROR, "dops_sillyrename - Could not add file");
        goto out;
    }

    if (!dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "dops_sillyrename - Could not flush dirnode");
        goto out;
    }

    /* move the filebox object name */
    codename1_str = encode_bin2str(codename1);
    codename2_str = encode_bin2str(codename2);

    path1 = uc_get_dnode_path(codename1_str);
    path2 = uc_get_dnode_path(codename2_str);

    if (rename(path1, path2)) {
        slog(0, SLOG_ERROR, "dirops_rename - renaming filebox failed");
        goto out;
    }

    *encoded_name_dest = codename2_str;

    error = 0;
out:
    if (codename1)
        free((void *)codename1);
    if (codename2)
        free((void *)codename2);
    if (codename1_str)
        free(codename1_str);
    if (codename2_str && error) {
        free(codename2_str);
    }
    if (path1)
        sdsfree(path1);
    if (path2)
        sdsfree(path2);
    dcache_put(dirnode);

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
    uc_dirnode_t *dirnode1 = NULL, *dirnode2 = NULL;
    encoded_fname_t *shadow1_bin = NULL, *shadow2_bin = NULL;
    char *shadow1_str = NULL, * shadow2_str = NULL;
    sds path1 = NULL, path2 = NULL;

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

    if (dirnode_equals(dirnode1, dirnode2)) {
        if (dirnode_rename(dirnode1, oldname, newname, type, &shadow1_bin,
                           &shadow2_bin)) {
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
        shadow1_bin = dirnode_rm(dirnode1, oldname, type, &atype);
        if (shadow1_bin == NULL) {
            slog(0, SLOG_ERROR, "dirops_move - Could not find '%s' in dirnode",
                 oldname);
            goto out;
        }

        // the new file might still exist in the dirnode
        dirnode_rm(dirnode2, newname, UCAFS_TYPE_UNKNOWN, &atype);
        shadow2_bin = dirnode_add(dirnode2, newname, atype);
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
    shadow1_str = encode_bin2str(shadow1_bin);
    if (shadow1_str == NULL) {
        slog(0, SLOG_ERROR, "dops_move - Could not convert shadowname to str");
        goto out;
    }

    shadow2_str = encode_bin2str(shadow2_bin);
    if (shadow2_str == NULL) {
        slog(0, SLOG_ERROR, "dops_move - Could not convert shadowname to str");
        goto out;
    }

    path1 = uc_get_dnode_path(shadow1_str);
    path2 = uc_get_dnode_path(shadow2_str);

    /* move the metadata file */
    if (type != UCAFS_TYPE_LINK) {
        if (rename(path1, path2)) {
            slog(0, SLOG_ERROR, "dops_move - renaming metadata file failed");
            goto out;
        }
    } else {
        slog(0, SLOG_WARN, "dops_move - renaming link (%s) %s -> %s", from_dir,
             oldname, newname);
    }

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

#if 0
int
dirops_rename(const char * from_path,
              const char * to_path,
              ucafs_entry_type type,
              char ** raw_name_dest)
{
    int error = AFSX_STATUS_NOOP;
    sds c_old_name = NULL, c_new_name = NULL;
    uc_dirnode_t *dirnode1 = NULL, *dirnode2 = NULL;
    const encoded_fname_t * fname_code = NULL;

    if ((c_old_name = do_get_fname(from_path)) == NULL) {
        goto out;
    }

    if ((c_new_name = do_get_fname(to_path)) == NULL) {
        goto out;
    }

    dirnode1 = dcache_get(from_path);
    dirnode2 = dcache_get(to_path);

    if (dirnode1 == NULL || dirnode2 == NULL) {
        slog(0, SLOG_ERROR, "Could not find dirnode");
        goto out;
    }

    error = AFSX_STATUS_ERROR;

    if (dirnode_equals(dirnode1, dirnode2)) {
        fname_code = dirnode_rename(dirnode1, c_old_name, c_new_name, type);
        if (fname_code == NULL) {
            slog(0, SLOG_ERROR, "Could not accomplish rename");
            goto out;
        }

        if (!dirnode_flush(dirnode1)) {
            slog(0, SLOG_ERROR, "Could not flush dirnode");
            goto out;
        }

        goto out1;
    }

    /* Removing from the owning dirnode */
    fname_code = dirnode_rm(dirnode1, c_old_name, type);
    if (fname_code == NULL) {
        slog(0, SLOG_ERROR, "fname '%s' does not exist", c_old_name);
        goto out;
    }

    if (!dirnode_flush(dirnode1)) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", from_path);
        goto out;
    }

    /* Adding it to the new dirnode */
    dirnode_rm(dirnode2, c_new_name, type);
    dirnode_add_alias(dirnode2, c_new_name, type, fname_code);

    if (!dirnode_flush(dirnode2)) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", to_path);
        goto out;
    }

out1:
    *raw_name_dest = encode_bin2str(fname_code);
    error = AFSX_STATUS_SUCCESS;
out:
    if (c_old_name)
        sdsfree(c_old_name);
    if (c_new_name)
        sdsfree(c_new_name);
    if (dirnode2)
        dcache_put(dirnode2);
    if (dirnode1)
        dcache_put(dirnode1);

    return error;
}
#endif

int
dirops_hardlink(const char * new_path,
                const char * old_path,
                char ** encoded_name_dest)
{
    int error = AFSX_STATUS_NOOP;
    char *fname = NULL, *temp = NULL;
    const encoded_fname_t * fname_code = NULL;
    sds new_fbox_path = NULL;
    uc_dirnode_t *old_dirnode = NULL, *new_dirnode = NULL;
    uc_filebox_t *old_filebox = NULL, *new_filebox = NULL;

    if ((old_filebox = dcache_get_filebox(old_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirops - filebox (%s) not found", old_path);
        goto out;
    }

    if ((new_dirnode = dcache_get(new_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirops - dirnode (%s) not found", new_path);
        goto out;
    }

    /* add the new entry to the new dirnode */
    if ((fname = do_get_fname(new_path)) == NULL) {
        slog(0, SLOG_ERROR, "dirops - getting file name from (%s)", new_path);
        goto out;
    }

    fname_code = dirnode_add(new_dirnode, fname, UCAFS_TYPE_FILE);
    if (fname_code == NULL) {
        slog(0, SLOG_ERROR, "Add file operation failed: %s", new_path);
        goto out;
    }

    if (!dirnode_flush(new_dirnode)) {
        slog(0, SLOG_ERROR, "Flushing '%s' dirnode failed", old_path);
        goto out;
    }

    /* create our new filebox */
    if ((new_filebox = filebox_from_fbox(old_filebox)) == NULL) {
        slog(0, SLOG_ERROR, "Creating '%s' filebox failed", new_filebox);
        goto out;
    }

    temp = encode_bin2str(fname_code);
    new_fbox_path = uc_get_dnode_path(temp);

    /* write it to disk */
    if (!filebox_write(new_filebox, new_fbox_path)) {
        // update the dirnode...
        slog(0, SLOG_ERROR, "Writing filebox '%s' failed", new_fbox_path);
        goto out;
    }

    *encoded_name_dest = temp;

    error = 0;
out:
    if (error && temp) {
        free(temp);
    }
    if (new_fbox_path)
        sdsfree(new_fbox_path);
    if (fname)
        sdsfree(fname);
    if (old_filebox)
        filebox_free(old_filebox);
    if (new_filebox)
        filebox_free(new_filebox);
    if (old_dirnode)
        dcache_put(old_dirnode);
    if (new_dirnode)
        dcache_put(new_dirnode);
    return error;
}

static int
encode_or_remove(const char * fpath,
                 ucafs_entry_type type,
                 char ** encoded_fname_dest,
                 bool rm)
{
    int error = -1; // TODO
    char *fname = NULL, *c_temp = NULL;
    const encoded_fname_t * fname_code = NULL;
    ucafs_entry_type atype;
    sds dnode_path = NULL;

    /* 1 - Get the corresponding dirnode */
    uc_dirnode_t * dirnode = dcache_get(fpath);
    if (dirnode == NULL) {
        goto out;
    }

    if ((fname = do_get_fname(fpath)) == NULL) {
        slog(0, SLOG_ERROR, "Could not get fname: %s", fpath);
        goto out;
    }

    /* Perform the operation */
    fname_code = rm ? dirnode_rm(dirnode, fname, type, &atype)
                    : dirnode_raw2enc(dirnode, fname, type, &atype);
    if (fname_code == NULL) {
        slog(0, SLOG_WARN, "Could not %s: %s", (rm ? "remove" : "find"), fpath);
        goto out;
    }

    if (rm && !dirnode_flush(dirnode)) {
        slog(0, SLOG_ERROR, "Error flushing: %s", fpath);
        goto out;
    }

    c_temp = encode_bin2str(fname_code);
    /* now delete the file from the filesystem */
    if (rm) {
        dcache_rm(fpath);
        dnode_path = uc_get_dnode_path(c_temp);
        if (type != UCAFS_TYPE_LINK && unlink(dnode_path)) {
            free(c_temp);
            slog(0, SLOG_ERROR, "Could not remove: %s", dnode_path);
            goto out;
        }
    }

    *encoded_fname_dest = c_temp;
    error = 0;
out:
    if (dirnode)
        dcache_put(dirnode);
    if (fname)
        sdsfree(fname);
    if (dnode_path)
        sdsfree(dnode_path);
    // dirnode only returns a new pointer when removing
    if (rm && fname_code)
        free((void *)fname_code);
    return error;
}

int
dirops_plain2code(const char * fpath_raw,
                  ucafs_entry_type type,
                  char ** encoded_fname_dest)
{
    return encode_or_remove(fpath_raw, type, encoded_fname_dest, false);
}

int
dirops_remove(const char * fpath_raw,
              ucafs_entry_type type,
              char ** encoded_fname_dest)
{
    return encode_or_remove(fpath_raw, type, encoded_fname_dest, true);
}
