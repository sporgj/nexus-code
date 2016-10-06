#include "uc_dnode.h"
#include "uc_uspace.h"

#include "dnode.pb.h"
#include "slog.h"

#include <iostream>

using namespace ::google::protobuf;

class dnode;

struct dirnode {
    dnode_header_t header;
    dnode * proto;
    sds dnode_path;
};

struct dirnode * dirnode_new()
{
    struct dirnode * obj = (struct dirnode *)malloc(sizeof(struct dirnode));
    if (obj == NULL) {
        return NULL;
    }

    memset(&obj->header, 0, sizeof(dnode_header_t));
    uuid_generate_time_safe(obj->header.uuid);
    obj->proto = new dnode();
    obj->dnode_path = NULL;

    return obj;
}

const sds dirnode_get_fpath(struct dirnode * dirnode) {
    return dirnode->dnode_path;
}

bool dirnode_equals(struct dirnode * dn1, struct dirnode * dn2)
{
    return memcmp(&dn1->header, &dn2->header, sizeof(dnode_header_t)) == 0;
}

void dirnode_free(struct dirnode * dirnode)
{
    delete dirnode->proto;

    if (dirnode->dnode_path) {
        sdsfree(dirnode->dnode_path);
    }

    free(dirnode);
}

struct dirnode * dirnode_default_dnode()
{
    struct dirnode * dn;
    sds path = uc_main_dnode_fpath();
    if (path == NULL) {
        return NULL;
    }

    dn = dirnode_from_file(path);
    sdsfree(path);

    return dn;
}

struct dirnode * dirnode_from_file(const sds filepath)
{
    struct dirnode * obj = NULL;
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
    if (header.len) {
        if ((buffer = (uint8_t *)malloc(header.len)) == NULL) {
            slog(0, SLOG_ERROR, "dirnode - allocation for dnode failed");
            goto out;
        }

        if ((nbytes = fread(buffer, 1, header.len, fd)) != header.len) {
            slog(0, SLOG_ERROR, "dirnode - reading protobuf failed:"
                    "expected=%u, actual=%u", header.len, nbytes);
            goto out;
        }

        if (!_dnode->ParseFromArray(buffer, header.len)) {
            slog(0, SLOG_ERROR, "dirnode - parsing protobuf failed: %s",
                filepath);
            goto out;
        }
    }

    obj = (struct dirnode *)malloc(sizeof(struct dirnode));
    if (obj == NULL) {
        slog(0, SLOG_ERROR, "dirnode - allocating dirnode object failed");
        goto out;
    }

    obj->dnode_path = sdsdup(filepath);
    obj->proto = _dnode;
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

bool dirnode_write(struct dirnode * dn, const char * fpath)
{
    bool ret = false;
    uint8_t * buffer = NULL;
    size_t len = CRYPTO_CEIL_TO_BLKSIZE(dn->proto->ByteSize());
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

    if (!dn->proto->SerializeToArray(buffer, len)) {
        slog(0, SLOG_ERROR, "dirnode - serialization failed");
        goto out;
    }

    /* GetCachedSize returns the size computed from ByteSize() */
    dn->header.len = dn->proto->GetCachedSize();

    fwrite(&dn->header, sizeof(dnode_header_t), 1, fd);
    fwrite(buffer, dn->header.len, 1, fd);

    ret = true;
out:
    fclose(fd);
    if (buffer) {
        free(buffer);
    }

    return ret;
}

bool dirnode_flush(struct dirnode * dn)
{
    assert(dn != NULL);
    return dn->dnode_path ? dirnode_write(dn, dn->dnode_path) : false;
}

const encoded_fname_t * dirnode_add_alias(struct dirnode * dn, const sds name,
    ucafs_entry_type type, const encoded_fname_t * p_encoded_name)
{
    encoded_fname_t * encoded_name;
    dnode_fentry * fentry;

    if (type == UCAFS_TYPE_UNKNOWN) {
        return NULL;
    }

    encoded_name = (encoded_fname_t *)malloc(sizeof(encoded_fname_t));
    if (encoded_name == NULL) {
        return nullptr;
    }

    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry = dn->proto->add_file();
        break;
    case UCAFS_TYPE_DIR:
        fentry = dn->proto->add_dir();
        break;
    case UCAFS_TYPE_LINK:
        fentry = dn->proto->add_link();
        break;
    default:
        return NULL;
    }

    if (p_encoded_name) {
        memcpy(encoded_name, p_encoded_name, sizeof(encoded_fname_t));
    } else {
        uuid_generate_time_safe(encoded_name->bin);
    }

    fentry->set_encoded_name(encoded_name, sizeof(encoded_fname_t));
    fentry->set_raw_name(name);

    dn->header.count++;

    return encoded_name;
}

const encoded_fname_t * dirnode_add(
    struct dirnode * dn, const sds name, ucafs_entry_type type)
{
    return dirnode_add_alias(dn, name, type, NULL);
}

const encoded_fname_t * dirnode_rm(
    struct dirnode * dn, const sds realname, ucafs_entry_type type)
{
    encoded_fname_t * result = NULL;
    RepeatedPtrField<dnode_fentry> * fentry_list;
    int len;
    bool iterate;

    if (type == UCAFS_TYPE_UNKNOWN) {
        type = UCAFS_TYPE_FILE;
        iterate = true;
    } else {
        iterate = false;
    }

retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = dn->proto->mutable_file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = dn->proto->mutable_dir();
        break;
    case UCAFS_TYPE_LINK:
        fentry_list = dn->proto->mutable_link();
        break;
    default:
        return NULL;
    }

    auto curr_fentry = fentry_list->begin();
    len = strlen(realname);

    while (curr_fentry != fentry_list->end()) {
        const string &str_entry = curr_fentry->raw_name();
        if (len == str_entry.size() &&
                memcmp(realname, str_entry.data(), len) == 0) {
            result = (encoded_fname_t *)malloc(sizeof(encoded_fname_t));
            if (result == NULL) {
                return NULL;
            }

            memcpy(result, curr_fentry->encoded_name().data(),
                sizeof(encoded_fname_t));

            // delete from the list
            fentry_list->erase(curr_fentry);
            dn->header.count--;
            return result;
        }

        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        case UCAFS_TYPE_DIR:
            type = UCAFS_TYPE_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return NULL;
}

const char * dirnode_enc2raw(const struct dirnode * dn,
    const encoded_fname_t * encoded_name, ucafs_entry_type type)
{
    const RepeatedPtrField<dnode_fentry> * fentry_list;

    bool iterate;
    if (type == UCAFS_TYPE_UNKNOWN) {
        type = UCAFS_TYPE_FILE;
        iterate = true;
    } else {
        iterate = false;
    }
retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = &dn->proto->file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = &dn->proto->dir();
        break;
    case UCAFS_TYPE_LINK:
        fentry_list = &dn->proto->link();
        break;
    default:
        return NULL;
    }

    auto curr_fentry = fentry_list->begin();
    while (curr_fentry != fentry_list->end()) {
        if (memcmp(encoded_name, curr_fentry->encoded_name().data(),
                sizeof(encoded_fname_t)) == 0) {
            return curr_fentry->raw_name().c_str();
        }

        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        case UCAFS_TYPE_DIR:
            type = UCAFS_TYPE_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return NULL;
}

const encoded_fname_t * dirnode_raw2enc(
    const struct dirnode * dn, const char * realname, ucafs_entry_type type)
{
    size_t len = strlen(realname);
    encoded_fname_t * encoded;
    const RepeatedPtrField<dnode_fentry> * fentry_list;

    bool iterate;
    if (type == UCAFS_TYPE_UNKNOWN) {
        type = UCAFS_TYPE_FILE;
        iterate = true;
    } else {
        iterate = false;
    }
retry:
    switch (type) {
    case UCAFS_TYPE_FILE:
        fentry_list = &dn->proto->file();
        break;
    case UCAFS_TYPE_DIR:
        fentry_list = &dn->proto->dir();
        break;
    case UCAFS_TYPE_LINK:
        fentry_list = &dn->proto->link();
        break;
    default:
        return NULL;
    }

    auto curr_fentry = fentry_list->begin();
    while (curr_fentry != fentry_list->end()) {
        const string& str_entry = curr_fentry->raw_name();

        if (len == str_entry.size() &&
                memcmp(realname, curr_fentry->raw_name().data(), len) == 0) {
            return (encoded_fname_t *)curr_fentry->encoded_name().data();
        }
        curr_fentry++;
    }

    if (iterate) {
        switch (type) {
        case UCAFS_TYPE_FILE:
            type = UCAFS_TYPE_DIR;
            goto retry;
            break;
        case UCAFS_TYPE_DIR:
            type = UCAFS_TYPE_LINK;
            goto retry;
            break;
        default:
            // TODO, go to link
            break;
        }
    }

    return NULL;
}

const encoded_fname_t * dirnode_rename(struct dirnode * dn,
    const sds oldname, const sds newname, ucafs_entry_type type)
{
    const encoded_fname_t * encoded_name = dirnode_rm(dn, oldname, type);
    const encoded_fname_t * p_encoded_name;
    if (encoded_name) {
        dirnode_rm(dn, newname, type);
        p_encoded_name = dirnode_add_alias(dn, newname, type, encoded_name);
        return encoded_name;
    }
    return NULL;
}

