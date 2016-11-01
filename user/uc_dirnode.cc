#include "uc_dirnode.h"
#include "uc_sgx.h"
#include "uc_uspace.h"

#include "dnode.pb.h"
#include "third/slog.h"

using namespace ::google::protobuf;

class dnode;

struct dirnode {
    dnode_header_t header;
    dnode * protobuf;
    sds dnode_path;
};

uc_dirnode_t *
dirnode_new()
{
    uc_dirnode_t * obj = (uc_dirnode_t *)malloc(sizeof(uc_dirnode_t));
    if (obj == NULL) {
        return NULL;
    }

    memset(&obj->header, 0, sizeof(dnode_header_t));
    uuid_generate_time_safe(obj->header.uuid);
    obj->protobuf = new dnode();
    obj->dnode_path = NULL;

    return obj;
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

        /* decrypt the content with enclave */
        ecall_crypto_dirnode(global_eid, &error, &header, buffer, UC_DECRYPT);
        if (error) {
            slog(0, SLOG_ERROR, "dirnode - enclave encryption failed");
            goto out;
        }

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
    size_t len = CRYPTO_CEIL_TO_BLKSIZE(dn->protobuf->ByteSize());
    FILE * fd;

    fd = fopen(fpath, "wb");
    if (fd == NULL) {
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
    dn->header.protolen = dn->protobuf->GetCachedSize();

    ecall_crypto_dirnode(global_eid, &error, &dn->header, buffer, UC_ENCRYPT);
    if (error) {
        slog(0, SLOG_ERROR, "dirnode - enclave encryption failed");
        goto out;
    }

    fwrite(&dn->header, sizeof(dnode_header_t), 1, fd);
    fwrite(buffer, dn->header.protolen, 1, fd);

    ret = true;
out:
    fclose(fd);
    if (buffer) {
        free(buffer);
    }

    return ret;
}

bool
dirnode_flush(uc_dirnode_t * dn)
{
    assert(dn != NULL);
    return dn->dnode_path ? dirnode_write(dn, dn->dnode_path) : false;
}

encoded_fname_t *
dirnode_add_alias(uc_dirnode_t * dn,
                  const char * name,
                  ucafs_entry_type type,
                  const encoded_fname_t * p_encoded_name,
                  const link_info_t * link_info)
{
    encoded_fname_t * encoded_name;
    dnode_dentry * dentry;

    if (type == UC_ANY) {
        slog(0, SLOG_ERROR, "dirnode_add - Entry type not specified");
        return NULL;
    }

    encoded_name = (encoded_fname_t *)malloc(sizeof(encoded_fname_t));
    if (encoded_name == NULL) {
        return nullptr;
    }

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
        return NULL;
    }

    if (p_encoded_name) {
        memcpy(encoded_name, p_encoded_name, sizeof(encoded_fname_t));
    } else {
        uuid_generate_time_safe(encoded_name->bin);
    }

    dentry->set_encoded_name(encoded_name, sizeof(encoded_fname_t));
    dentry->set_raw_name(name);

    /* if we have link info */
    if (link_info) {
        dentry->set_link_info(link_info, link_info->total_len);
    }

    dn->header.count++;

    return encoded_name;
}

encoded_fname_t *
dirnode_add(uc_dirnode_t * dn, const char * name, ucafs_entry_type type)
{
    return dirnode_add_alias(dn, name, type, NULL, NULL);
}

encoded_fname_t *
dirnode_add_link(uc_dirnode_t * dn,
                 const char * link_name,
                 const link_info_t * link_info)
{
    return dirnode_add_alias(dn, link_name, UC_LINK, NULL, link_info);
}

encoded_fname_t *
dirnode_rm(uc_dirnode_t * dn,
           const char * realname,
           ucafs_entry_type type,
           ucafs_entry_type * p_type,
           link_info_t ** pp_link_info)
{
    encoded_fname_t * result = NULL;
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

retry:
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
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    len = strlen(realname);

    while (curr_dentry != dentry_list->end()) {
        const string & str_entry = curr_dentry->raw_name();
        if (len == str_entry.size()
            && memcmp(realname, str_entry.data(), len) == 0) {
            result = (encoded_fname_t *)malloc(sizeof(encoded_fname_t));
            if (result == NULL) {
                return NULL;
            }

            /* send the link info */
            if (pp_link_info && curr_dentry->has_link_info()) {
                link_len = curr_dentry->link_info().size();
                link_info = (link_info_t *)malloc(link_len);
                if (link_info == NULL) {
                    slog(0, SLOG_ERROR, "allocating link_info space failed"
                            " len=%d", link_len);
                    return NULL;
                }

                memcpy(link_info, curr_dentry->link_info().data(), link_len);
                *pp_link_info = link_info;
            }

            memcpy(result, curr_dentry->encoded_name().data(),
                   sizeof(encoded_fname_t));

            // delete from the list
            dentry_list->erase(curr_dentry);
            dn->header.count--;
            *p_type = type;
            return result;
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

    return NULL;
}

const char *
dirnode_enc2raw(const uc_dirnode_t * dn,
                const encoded_fname_t * encoded_name,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    const RepeatedPtrField<dnode_dentry> * dentry_list;
    int ret;

    bool iterate;
    if (type == UC_ANY) {
        type = UC_FILE;
        iterate = true;
    } else {
        iterate = false;
    }
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
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    while (curr_dentry != dentry_list->end()) {
        ret = memcmp(encoded_name, curr_dentry->encoded_name().data(),
                     sizeof(encoded_fname_t));
        if (ret == 0) {
            *p_type = type;
            return curr_dentry->raw_name().c_str();
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

    return NULL;
}

static const encoded_fname_t *
__dirnode_raw2enc(const uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type,
                ucafs_entry_type * p_type,
                const link_info_t ** pp_link_info)
{
    size_t len = strlen(realname);
    encoded_fname_t * encoded;
    const RepeatedPtrField<dnode_dentry> * dentry_list;

    bool iterate;
    if (type == UC_ANY) {
        type = UC_FILE;
        iterate = true;
    } else {
        iterate = false;
    }
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
        return NULL;
    }

    auto curr_dentry = dentry_list->begin();
    while (curr_dentry != dentry_list->end()) {
        const string & str_entry = curr_dentry->raw_name();

        if (len == str_entry.size()
            && memcmp(realname, curr_dentry->raw_name().data(), len) == 0) {
            *p_type = type;

            /* check if we are traversing */
            if (pp_link_info && curr_dentry->has_link_info()) {
                *pp_link_info = (link_info_t *)curr_dentry->link_info().data();
            }

            return (encoded_fname_t *)curr_dentry->encoded_name().data();
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

    return NULL;
}

const encoded_fname_t *
dirnode_raw2enc(const uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    return __dirnode_raw2enc(dn, realname, type, p_type, NULL);
}

const encoded_fname_t *
dirnode_traverse(const uc_dirnode_t * dn,
                 const char * realname,
                 ucafs_entry_type type,
                 ucafs_entry_type * p_type,
                 const link_info_t ** pp_link_info)
{
    return __dirnode_raw2enc(dn, realname, type, p_type, pp_link_info);
}

int
dirnode_rename(uc_dirnode_t * dn,
               const char * oldname,
               const char * newname,
               ucafs_entry_type type,
               encoded_fname_t ** ptr_shadow1_bin,
               encoded_fname_t ** ptr_shadow2_bin,
               link_info_t ** pp_link_info1,
               link_info_t ** pp_link_info2)
{
    encoded_fname_t * shadow2_bin;
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

        *ptr_shadow2_bin = shadow2_bin;
        return shadow2_bin == NULL ? -1 : 0;
    }
    return -1;
}
