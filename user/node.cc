#include "node.h"
#include "slog.h"
#include "uspace.h"

struct dirnode * dn_new()
{
    struct dirnode * obj = (struct dirnode *)malloc(sizeof(struct dirnode));
    if (obj == NULL) {
        return NULL;
    }

    memset(&obj->header, 0, sizeof(dnode_header_t));
    uuid_generate_time_safe(obj->header.uuid);
    obj->proto = new dnode();

    return obj;
}

void dn_free(struct dirnode * dirnode)
{
    delete dirnode->proto;
    free(dirnode);
    if (dirnode->dnode_path) {
        sds_free(dirnode->dnode_path);
    }
}

struct dirnode * dn_default_dnode()
{
    struct dirnode * dn;
    sds path = uspace_default_dirnode_path();
    if (path) {
        return NULL;
    }

    dn = dn_from_file(path);
    sds_free(path);

    return dn;
}

struct dirnode * dn_from_file(const sds filepath)
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
    if (nbytes != sizeof(dnode_header_t)) {
        slog(0, SLOG_ERROR, "dirnode - could not read header: %s", filepath);
        goto out;
    }

    _dnode = new dnode();
    if (header.len) {
        if ((buffer = (uint8_t *)malloc(header.len)) == NULL) {
            slog(0, SLOG_ERROR, "dirnode - allocation for dnode failed");
            goto out;
        }

        if ((nbytes = fread(buffer, header.len, 1, fd)) != header.len) {
            slog(0, SLOG_ERROR, "dirnode - reading protobuf failed: %s",
                filepath);
            slog(0, SLOG_ERROR, "dirnode - expected=%u, actual=%u", header.len,
                nbytes);
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

bool dn_write(struct dirnode * dn, const char * fpath)
{
    bool ret = false;
    uint8_t * buffer;
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

    ret = true;
out:
    fclose(fd);
    if (buffer) {
        free(buffer);
    }
}

bool dn_flush(struct dirnode * dn)
{
    assert(dn != NULL);
    return dn->dnode_path ? dn_write(dn, dn->dnode_path) : false;
}

const encoded_fname_t * dn_add_alias(struct dirnode * dn, const sds name, ucafs_entry_type type,
    const encoded_fname_t * p_encoded_name)
{
    encoded_fname_t * encoded_name;
    dnode_fentry * fentry;

    if (type == UCAFS_TYPE_UNKNOWN) {
        return NULL;
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

    encoded_name = new encoded_fname_t;
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

const encoded_fname_t * dn_add(struct dirnode * dn, const sds name, ucafs_entry_type type)
{
    return dn_add_alias(dn, type, NULL);
}

