#include "uc_dirnode.h"
#include "uc_encode.h"
#include "uc_metadata.h"
#include "uc_sgx.h"
#include "uc_uspace.h"

#include "dnode.pb.h"
#include "third/slog.h"

using namespace ::google::protobuf;

class dnode;

struct dirnode {
    dnode_header_t header;
    dnode * protobuf;
    const struct uc_dentry * dentry;
    sds dnode_path;

    /* live object stuff */
    int is_dirty;
    struct metadata_entry * mcache;
    uv_mutex_t lock;
};

uc_dirnode_t *
dirnode_new_alias(const shadow_t * id)
{
    uc_dirnode_t * obj = (uc_dirnode_t *)malloc(sizeof(uc_dirnode_t));
    if (obj == NULL) {
        return NULL;
    }

    memset(&obj->header, 0, sizeof(dnode_header_t));
    if (id) {
        memcpy(&obj->header.uuid, id, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe((uint8_t *)&obj->header.uuid);
    }
    obj->protobuf = new dnode();
    obj->dnode_path = NULL;
    obj->dentry = NULL;

    return obj;
}

uc_dirnode_t *
dirnode_new()
{
    return dirnode_new_alias(NULL);
}

void
dirnode_set_parent(uc_dirnode_t * dirnode, const uc_dirnode_t * parent)
{
    memcmp(&dirnode->header.parent, &parent->header.uuid, sizeof(shadow_t));
}

const shadow_t *
dirnode_get_parent(uc_dirnode_t * dirnode)
{
    return &dirnode->header.parent;
}

void
dirnode_set_dentry(uc_dirnode_t * dirnode, const struct uc_dentry * dentry)
{
    dirnode->dentry = dentry;
}

const struct uc_dentry *
dirnode_get_dentry(uc_dirnode_t * dirnode)
{
    return dirnode->dentry;
}

void
dirnode_clear_dentry(uc_dirnode_t * dirnode)
{
    dirnode->dentry = NULL;
}

struct metadata_entry * dirnode_get_metadata(uc_dirnode_t * dn)
{
    return dn->mcache;
}

void dirnode_set_metadata(uc_dirnode_t * dn, struct metadata_entry * entry)
{
    // XXX get the lock here?
    dn->mcache = entry;
}

int
dirnode_is_root(uc_dirnode_t * dirnode)
{
    return dirnode->header.is_root;
}

const sds
dirnode_get_fpath(uc_dirnode_t * dirnode)
{
    return dirnode->dnode_path;
}

bool
dirnode_equals(uc_dirnode_t * dn1, uc_dirnode_t * dn2)
{
    return memcmp(&dn1->header, &dn2->header, sizeof(dnode_header_t)) == 0;
}

void
dirnode_free(uc_dirnode_t * dirnode)
{
    delete dirnode->protobuf;

    if (dirnode->dnode_path) {
        sdsfree(dirnode->dnode_path);
    }

    free(dirnode);
}

uc_dirnode_t *
dirnode_default_dnode()
{
    uc_dirnode_t * dn;
    sds path = uc_main_dnode_fpath();
    if (path == NULL) {
        return NULL;
    }

    dn = dirnode_from_file(path);
    sdsfree(path);

    return dn;
}

uc_dirnode_t *
dirnode_from_shadow_name(const shadow_t * shdw_name)
{
    sds path_sds;

    if (memcmp(shdw_name, &uc_root_dirnode_shadow_name, sizeof(shadow_t)) == 0) {
        path_sds = uc_main_dnode_fpath();
    } else {
        char * temp = metaname_bin2str(shdw_name);
        path_sds = uc_get_dnode_path(temp);
        free(temp);
    }

    uc_dirnode_t * dn = dirnode_from_file(path_sds);
    sdsfree(path_sds);
    return dn;
}

uc_dirnode_t *
dirnode_from_file(const sds filepath)
{
    uc_dirnode_t * obj = NULL;
    dnode * _dnode = NULL;
    dnode_header_t header;
    uint8_t * buffer = NULL;
    FILE * fd;
    size_t nbytes;
    int error = -1;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        slog(0, SLOG_ERROR, "dirnode - could not open: %s", filepath);
        return NULL;
    }

    /* read the header from the file */
    nbytes = fread(&header, sizeof(dnode_header_t), 1, fd);
    if (!nbytes) {
        slog(0, SLOG_ERROR, "dirnode - could not read header: %s (nbytes=%u)",
             filepath, nbytes);
        goto out;
    }

    _dnode = new dnode();
    if (header.protolen) {
        if ((buffer = (uint8_t *)malloc(header.protolen)) == NULL) {
            slog(0, SLOG_ERROR, "dirnode - allocation for dnode failed");
            goto out;
        }

        if ((nbytes = fread(buffer, 1, header.protolen, fd))
            != header.protolen) {
            slog(0, SLOG_ERROR, "dirnode - reading protobuf failed:"
                                "expected=%u, actual=%u",
                 header.protolen, nbytes);
            goto out;
        }

#ifdef UCAFS_SGX
        /* decrypt the content with enclave */
        ecall_crypto_dirnode(global_eid, &error, &header, buffer, UC_DECRYPT);
        if (error) {
            slog(0, SLOG_ERROR, "dirnode - enclave encryption failed");
            goto out;
        }
#endif

        if (!_dnode->ParseFromArray(buffer, header.protolen)) {
            slog(0, SLOG_ERROR, "dirnode - parsing protobuf failed: %s",
                 filepath);
            goto out;
        }
    }

    obj = (uc_dirnode_t *)malloc(sizeof(uc_dirnode_t));
    if (obj == NULL) {
        slog(0, SLOG_ERROR, "dirnode - allocating dirnode object failed");
        goto out;
    }

    obj->dnode_path = sdsdup(filepath);
    obj->protobuf = _dnode;
    obj->dentry = NULL;
    obj->is_dirty = 0;
    uv_mutex_init(&obj->lock);
    obj->mcache = NULL;

    memcpy(&obj->header, &header, sizeof(dnode_header_t));

    error = 0;
out:
    if (error) {
        // free the object
        delete _dnode;
    }

    if (buffer) {
        free(buffer);
    }

    fclose(fd);
    return obj;
}

bool
dirnode_write(uc_dirnode_t * dn, const char * fpath)
{
    bool ret = false;
    int error;
    uint8_t * buffer = NULL;
    FILE * fd;
    size_t len;

    len = dn->protobuf->ByteSize();

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
        uv_mutex_unlock(&dn->lock);
        slog(0, SLOG_ERROR, "dirnode - file not found: %s", fpath);
        return false;
    }

    if ((buffer = (uint8_t *)malloc(len)) == NULL) {
        slog(0, SLOG_ERROR, "dirnode - alloc error for write buffer");
        goto out;
    }

    if (!dn->protobuf->SerializeToArray(buffer, len)) {
        slog(0, SLOG_ERROR, "dirnode - serialization failed");
        goto out;
    }

    /* GetCachedSize returns the size computed from ByteSize() */
    dn->header.protolen = len;

#ifdef UCAFS_SGX
    ecall_crypto_dirnode(global_eid, &error, &dn->header, buffer, UC_ENCRYPT);
    if (error) {
        slog(0, SLOG_ERROR, "dirnode - enclave encryption failed");
        goto out;
    }
#endif

    fwrite(&dn->header, sizeof(dnode_header_t), 1, fd);
    fwrite(buffer, dn->header.protolen, 1, fd);

    ret = true;
out:
    fclose(fd);
    if (buffer) {
        free(buffer);
    }

    dn->is_dirty = 0;

    return ret;
}

bool
dirnode_flush(uc_dirnode_t * dn)
{
    assert(dn != NULL);
    return true;
}

bool
dirnode_fsync(uc_dirnode_t * dn)
{
    return dn->dnode_path ? dirnode_write(dn, dn->dnode_path) : false;
}

shadow_t *
dirnode_add_alias(uc_dirnode_t * dn,
                  const char * name,
                  ucafs_entry_type type,
                  const shadow_t * p_encoded_name,
                  const link_info_t * link_info)
{
    shadow_t * encoded_name;
    dnode_dentry * dentry;

    if (type == UC_ANY) {
        slog(0, SLOG_ERROR, "dirnode_add - Entry type not specified");
        return NULL;
    }

    encoded_name = (shadow_t *)malloc(sizeof(shadow_t));
    if (encoded_name == NULL) {
        return nullptr;
    }

    uv_mutex_lock(&dn->lock);
    switch (type) {
    case UC_FILE:
        dentry = dn->protobuf->add_file();
        break;
    case UC_DIR:
        dentry = dn->protobuf->add_dir();
        break;
    case UC_LINK:
        dentry = dn->protobuf->add_link();
        break;
    default:
        uv_mutex_unlock(&dn->lock);
        return NULL;
    }

    if (p_encoded_name) {
        memcpy(encoded_name, p_encoded_name, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe(encoded_name->bin);
    }

    dentry->set_encoded_name(encoded_name, sizeof(shadow_t));
    dentry->set_raw_name(name);

    /* if we have link info */
    if (link_info) {
        dentry->set_link_info(link_info, link_info->total_len);
    }

    dn->header.count++;

    if (dn->is_dirty == 0) {
        metadata_dirty_dirnode(dn);
        dn->is_dirty = 1;
    }

    uv_mutex_unlock(&dn->lock);
    return encoded_name;
}

shadow_t *
dirnode_add(uc_dirnode_t * dn, const char * name, ucafs_entry_type type)
{
    return dirnode_add_alias(dn, name, type, NULL, NULL);
}

shadow_t *
dirnode_add_link(uc_dirnode_t * dn,
                 const char * link_name,
                 const link_info_t * link_info)
{
    return dirnode_add_alias(dn, link_name, UC_LINK, NULL, link_info);
}

shadow_t *
dirnode_rm(uc_dirnode_t * dn,
           const char * realname,
           ucafs_entry_type type,
           ucafs_entry_type * p_type,
           link_info_t ** pp_link_info)
{
    shadow_t * result = NULL;
    RepeatedPtrField<dnode_dentry> * dentry_list;
    int len, link_len;
    bool iterate;
    link_info_t * link_info;

    if (type == UC_ANY) {
        type = UC_FILE;
        iterate = true;
    } else {
        iterate = false;
    }

    uv_mutex_lock(&dn->lock);
retry:
    *pp_link_info = NULL;

    switch (type) {
    case UC_FILE:
        dentry_list = dn->protobuf->mutable_file();
        break;
    case UC_DIR:
        dentry_list = dn->protobuf->mutable_dir();
        break;
    case UC_LINK:
        dentry_list = dn->protobuf->mutable_link();
        break;
    default:
        uv_mutex_unlock(&dn->lock);
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    len = strlen(realname);

    while (curr_dentry != dentry_list->end()) {
        const string & str_entry = curr_dentry->raw_name();
        if (len == str_entry.size()
            && memcmp(realname, str_entry.data(), len) == 0) {
            result = (shadow_t *)malloc(sizeof(shadow_t));
            if (result == NULL) {
                slog(0, SLOG_FATAL, "allocation error");
                goto out;
            }

            /* send the link info */
            if (pp_link_info && curr_dentry->has_link_info()) {
                link_len = curr_dentry->link_info().size();
                link_info = (link_info_t *)malloc(link_len);
                if (link_info == NULL) {
                    free(result);
                    result = NULL;

                    slog(0, SLOG_ERROR, "allocating link_info space failed"
                                        " len=%d",
                         link_len);
                    goto out;
                }

                memcpy(link_info, curr_dentry->link_info().data(), link_len);
                *pp_link_info = link_info;
            }

            memcpy(result, curr_dentry->encoded_name().data(),
                   sizeof(shadow_t));

            // delete from the list
            dentry_list->erase(curr_dentry);
            dn->header.count--;
            *p_type = type;
            goto out;
        }

        curr_dentry++;
    }

    if (iterate) {
        switch (type) {
        case UC_FILE:
            type = UC_DIR;
            goto retry;
            break;
        case UC_DIR:
            type = UC_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

out:
    if (result && dn->is_dirty == 0) {
        metadata_dirty_dirnode(dn);
        dn->is_dirty = 1;
    }

    uv_mutex_unlock(&dn->lock);

    return result;
}

const char *
dirnode_enc2raw(uc_dirnode_t * dn,
                const shadow_t * encoded_name,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    const RepeatedPtrField<dnode_dentry> * dentry_list;
    const char * result = NULL;
    int ret;

    bool iterate;
    if (type == UC_ANY) {
        type = UC_FILE;
        iterate = true;
    } else {
        iterate = false;
    }

    uv_mutex_lock(&dn->lock);
retry:
    switch (type) {
    case UC_FILE:
        dentry_list = &dn->protobuf->file();
        break;
    case UC_DIR:
        dentry_list = &dn->protobuf->dir();
        break;
    case UC_LINK:
        dentry_list = &dn->protobuf->link();
        break;
    default:
        uv_mutex_unlock(&dn->lock);
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    while (curr_dentry != dentry_list->end()) {
        ret = memcmp(encoded_name, curr_dentry->encoded_name().data(),
                     sizeof(shadow_t));
        if (ret == 0) {
            *p_type = type;
            result = curr_dentry->raw_name().c_str();
            goto out;
        }

        curr_dentry++;
    }

    if (iterate) {
        switch (type) {
        case UC_FILE:
            type = UC_DIR;
            goto retry;
            break;
        case UC_DIR:
            type = UC_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

out:
    uv_mutex_unlock(&dn->lock);
    return result;
}

static const shadow_t *
__dirnode_raw2enc(uc_dirnode_t * dn,
                  const char * realname,
                  ucafs_entry_type type,
                  ucafs_entry_type * p_type,
                  const link_info_t ** pp_link_info)
{
    size_t len = strlen(realname);
    const shadow_t * encoded = NULL;
    const RepeatedPtrField<dnode_dentry> * dentry_list;

    bool iterate;
    if (type == UC_ANY) {
        type = UC_FILE;
        iterate = true;
    } else {
        iterate = false;
    }

    uv_mutex_lock(&dn->lock);
retry:
    switch (type) {
    case UC_FILE:
        dentry_list = &dn->protobuf->file();
        break;
    case UC_DIR:
        dentry_list = &dn->protobuf->dir();
        break;
    case UC_LINK:
        dentry_list = &dn->protobuf->link();
        break;
    default:
        uv_mutex_unlock(&dn->lock);
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    while (curr_dentry != dentry_list->end()) {
        const string & str_entry = curr_dentry->raw_name();

        if (len == str_entry.size()
            && memcmp(realname, str_entry.data(), len) == 0) {
            *p_type = type;

            /* check if we are traversing */
            if (pp_link_info && curr_dentry->has_link_info()) {
                *pp_link_info = (link_info_t *)curr_dentry->link_info().data();
            }

            encoded = (const shadow_t *)curr_dentry->encoded_name().data();
            goto out;
        }
        curr_dentry++;
    }

    if (iterate) {
        switch (type) {
        case UC_FILE:
            type = UC_DIR;
            goto retry;
            break;
        case UC_DIR:
            type = UC_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

out:
    uv_mutex_unlock(&dn->lock);
    return encoded;
}

const shadow_t *
dirnode_raw2enc(uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    return __dirnode_raw2enc(dn, realname, type, p_type, NULL);
}

const shadow_t *
dirnode_traverse(uc_dirnode_t * dn,
                 const char * realname,
                 ucafs_entry_type type,
                 ucafs_entry_type * p_type,
                 const link_info_t ** pp_link_info)
{
    return __dirnode_raw2enc(dn, realname, type, p_type, pp_link_info);
}

// TODO fix locking
int
dirnode_rename(uc_dirnode_t * dn,
               const char * oldname,
               const char * newname,
               ucafs_entry_type type,
               ucafs_entry_type * p_type,
               shadow_t ** ptr_shadow1_bin,
               shadow_t ** ptr_shadow2_bin,
               link_info_t ** pp_link_info1,
               link_info_t ** pp_link_info2)
{
    shadow_t * shadow2_bin;
    ucafs_entry_type atype, atype1;

    *ptr_shadow2_bin = NULL;

    *ptr_shadow1_bin = dirnode_rm(dn, oldname, type, &atype, pp_link_info1);
    if (*ptr_shadow1_bin) {
        // it is necessary to return the codename of the existing entry
        // otherwise, we get a lingering file in the AFS server
        //
        // Pass the UNKOWN flag to ensure any copy of the existing file is
        // erased
        shadow2_bin = dirnode_rm(dn, newname, UC_ANY, &atype1, pp_link_info2);
        if (shadow2_bin == NULL) {
            shadow2_bin = dirnode_add(dn, newname, atype);
        } else {
            // in case the source was a link, its information gets carried over
            shadow2_bin = dirnode_add_alias(dn, newname, atype, shadow2_bin,
                                            *pp_link_info1);
        }

        *p_type = atype;
        *ptr_shadow2_bin = shadow2_bin;
        return shadow2_bin == NULL ? -1 : 0;
    }
    return -1;
}

int dirnode_trylock(uc_dirnode_t * dn)
{
    return uv_mutex_trylock(&dn->lock);
}

void dirnode_unlock(uc_dirnode_t * dn)
{
    uv_mutex_unlock(&dn->lock);
}
