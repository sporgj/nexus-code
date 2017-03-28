#include "uc_encode.h"
#include "uc_sgx.h"
#include "uc_uspace.h"
#include "uc_utils.h"
#include "uc_vfs.h"

#include "third/log.h"

static int
serialize_lockbox(uc_dirnode_t * dn, uint8_t * buffer);

static int
parse_lockbox(uc_dirnode_t * dn, uint8_t * buffer);

static int
serialize_dirbox(uc_dirnode_t * dn, uint8_t * buffer);

static int
parse_dirbox(uc_dirnode_t * dn, uint8_t * buffer);

uc_dirnode_t *
dirnode_new2(const shadow_t * id, const uc_dirnode_t * parent)
{
    uc_dirnode_t * dn = (uc_dirnode_t *)malloc(sizeof(uc_dirnode_t));
    if (dn == NULL) {
        return NULL;
    }

    memset(&dn->header, 0, sizeof(dirnode_header_t));
    if (id) {
        memcpy(&dn->header.uuid, id, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe((uint8_t *)&dn->header.uuid);
    }

    TAILQ_INIT(&dn->dirbox);
    SIMPLEQ_INIT(&dn->lockbox);
    TAILQ_INIT(&dn->buckets);
    dn->bucket_update = false;

    dn->dnode_path = NULL;
    dn->dentry = NULL;
    dn->header.bucket_count = 1;

    /* create the default bucket */
    dn->bucket0 = calloc(1, sizeof(dirnode_bucket_entry_t));
    if (dn->bucket0 == NULL) {
        log_fatal("allocation error");
        free(dn);
        return NULL;
    }

    dn->bucket0->freeable = true;

    TAILQ_INSERT_HEAD(&dn->buckets, dn->bucket0, next_entry);

    if (parent) {
        memcpy(&dn->header.parent, &parent->header.uuid, sizeof(shadow_t));
        memcpy(&dn->header.root, &parent->header.root, sizeof(shadow_t));
    }

    return dn;
}

uc_dirnode_t *
dirnode_new_root(const shadow_t * id)
{
    uc_dirnode_t * dn;
    if ((dn = dirnode_new2(id, NULL)) == NULL) {
        return NULL;
    }

    /* make sure we put stuff that makes it lok like root */
    memcpy(&dn->header.parent, id, sizeof(shadow_t));
    memcpy(&dn->header.root, id, sizeof(shadow_t));

    return dn;
}

uc_dirnode_t *
dirnode_new_alias(const shadow_t * id)
{
    return dirnode_new2(id, NULL);
}

uc_dirnode_t *
dirnode_new()
{
    return dirnode_new_alias(NULL);
}

static inline void
free_dnode_entry(dnode_list_entry_t * list_entry)
{
    if (list_entry->dnode_data.target) {
        free(list_entry->dnode_data.target);
    }

    free(list_entry);
}

void
dirnode_free(uc_dirnode_t * dirnode)
{
    dnode_list_head_t * dir_head = &dirnode->dirbox;
    acl_list_head_t * acl_head = &dirnode->lockbox;
    bucket_list_head_t * bucket_head = &dirnode->buckets;

    dnode_list_entry_t * dnode_entry;
    acl_list_entry_t * acl_entry;
    dirnode_bucket_entry_t * bucket_entry;

    /* clear the entries in the entries */
    while ((dnode_entry = TAILQ_FIRST(dir_head))) {
        TAILQ_REMOVE(dir_head, dnode_entry, next_entry);
        free_dnode_entry(dnode_entry);
    }

    /* clear lockbox entries */
    while ((acl_entry = SIMPLEQ_FIRST(acl_head))) {
        SIMPLEQ_REMOVE_HEAD(acl_head, next_entry);
        free(acl_entry);
    }

    /* clear the buckets */
    while ((bucket_entry = TAILQ_LAST(bucket_head, bucket_list))) {
        TAILQ_REMOVE(bucket_head, bucket_entry, next_entry);
        if (bucket_entry->freeable) {
            free(bucket_entry);
        }
    }

    if (dirnode->dnode_path) {
        sdsfree(dirnode->dnode_path);
    }

    free(dirnode);
}

uc_dirnode_t *
dirnode_from_file(const sds filepath)
{
    uc_dirnode_t * dn = NULL;
    dirnode_header_t * header;
    dnode_list_head_t * dirbox;
    acl_list_head_t * lockbox;
    bucket_list_head_t * buckets;
    dirnode_bucket_entry_t * bucket0;
    uint8_t *buffer = NULL, *offset_ptr = NULL;
    FILE *fd, *fd2 = NULL;
    sds path2 = NULL;
    size_t nbytes, body_len;
    int error = -1;

    fd = fopen(filepath, "rb");
    if (fd == NULL) {
        log_error("opening '%s' failed", filepath);
        return NULL;
    }

    /* instantiate our objects */
    if ((dn = calloc(sizeof(uc_dirnode_t), 1)) == NULL) {
        log_fatal("allocation failed");
        fclose(fd);
        return NULL;
    }

    header = &dn->header;
    dirbox = &dn->dirbox;
    lockbox = &dn->lockbox;
    buckets = &dn->buckets;

    TAILQ_INIT(dirbox);
    SIMPLEQ_INIT(lockbox);
    TAILQ_INIT(buckets);

    /* read the header from the file */
    nbytes = fread(header, sizeof(dirnode_header_t), 1, fd);
    if (!nbytes) {
        log_error("reading header: %s (nbytes=%zu, exp=%lu)", filepath, nbytes,
                  sizeof(dirnode_header_t));
        goto out;
    }

    /* initialize the buckets */
    dirnode_bucket_entry_t * bucket_list = (dirnode_bucket_entry_t *)calloc(
        header->bucket_count, sizeof(dirnode_bucket_entry_t));
    if (bucket_list == NULL) {
        log_fatal("allocation error");
        goto out;
    }

    /* assign bucket 0 */
    (dn->bucket0 = bucket0 = &bucket_list[0])->freeable = true;

    for (size_t x = 0; x < header->bucket_count; x++) {
        // copy the iv, tag, length and count data
        if (!fread(&bucket_list[x].bckt, sizeof(dirnode_bucket_t), 1, fd)) {
            log_error("reading bucket failed (%s)", filepath);
            goto out;
        }

        // please note that the other buckets -> freeable = false

        TAILQ_INSERT_TAIL(buckets, &bucket_list[x], next_entry);
    }

    /* lets try to read the body of the dirnode */
    // TODO maybe check when body_len is ridiculous?
    body_len = header->dirbox_len + header->lockbox_len;
    if (!body_len) {
        goto done;
    }

    if ((buffer = (uint8_t *)malloc(body_len)) == NULL) {
        log_fatal("allocation for dnode failed");
        goto out;
    }

    /* lets read bucket0 */
    nbytes = fread(buffer, 1, bucket0->bckt.length, fd);
    bucket0->buffer = buffer;
    fclose(fd);
    fd = NULL;

    /* move the pointer where the next file will be read */
    offset_ptr = buffer;

    /* read the remaining files */
    int x = -1;
    dirnode_bucket_entry_t * bucket_entry;
    TAILQ_FOREACH(bucket_entry, &dn->buckets, next_entry)
    {
        x++;
        if (bucket_entry == bucket0) {
            offset_ptr += bucket_entry->bckt.length;
            continue;
        }

        path2 = string_and_number(filepath, x);

        fd2 = fopen(path2, "rb");
        if (fd2 == NULL) {
            log_error("opening '%s' FAILED", path2);
            goto out;
        }

        // copy the iv, tag and count data
        if (!fread(offset_ptr, bucket_entry->bckt.length, 1, fd2)) {
            log_error("reading bucket failed (%s)", path2);
            goto out;
        }

        bucket_entry->buffer = offset_ptr;
        offset_ptr += bucket_entry->bckt.length;

        sdsfree(path2);
        fclose(fd2);

        path2 = NULL;
        fd2 = NULL;
    }

#ifdef UCAFS_SGX
    /* decrypt the content with enclave */
    ecall_dirnode_crypto(global_eid, &error, dn, UC_DECRYPT);
    if (error) {
        log_error("enclave dirnode decryption failed");
        goto out;
    }
#endif

    /* parse the body */
    offset_ptr = buffer;
    if (header->lockbox_len && parse_lockbox(dn, offset_ptr)) {
        log_error("parsing lockbox failed: %s", filepath);
        goto out;
    }

    offset_ptr += header->lockbox_len;
    if (header->dirbox_len && parse_dirbox(dn, offset_ptr)) {
        log_error("parsing dirbox failed: %s", filepath);
        goto out;
    }

    /* adjust the size of bucket0 */
    bucket0->bckt.length -= header->lockbox_len;

done:
    dn->dnode_path = sdsdup(filepath);
    error = 0;

out:
    if (error) {
        dirnode_free(dn);
        dn = NULL;
    }

    if (buffer) {
        free(buffer);
    }

    if (fd2) {
        fclose(fd2);
    }

    if (fd) {
        fclose(fd);
    }

    return dn;
}

bool
dirnode_write(uc_dirnode_t * dn, const char * fpath)
{
    bool ret = false, preexist = true;
    int error;
    uint8_t *buffer = NULL, *offset_ptr = NULL;
    sds path2 = NULL;
    FILE *fd, *fd2 = NULL;
    size_t proto_len, total_len = 0, nbytes;
    dirnode_bucket_entry_t * bucket0 = dn->bucket0, *bucket_entry;

    /* if the file exists, do not overwrite */
    fd = fopen(fpath, bucket0->is_dirty ? "wb" : "rb+");
    if (fd == NULL) {
        preexist = false;

        if ((fd = fopen(fpath, "wb")) == NULL) {
            log_error("file not found: %s", fpath);
            return false;
        }
    }

    if (!preexist || dn->bucket_update) {
        bucket0->is_dirty = true;
    }

    /* if it's dirty, then we have to add ACL information */
    if (bucket0->is_dirty) {
        total_len += dn->header.lockbox_len;
    }

    /* iterate through every bucket entry and only include their sizes */
    TAILQ_FOREACH(bucket_entry, &dn->buckets, next_entry) {
        if (bucket_entry->is_dirty) {
            total_len += bucket_entry->bckt.length;
        }
    }

    /* allocate the buffer that will hold everything */
    if ((buffer = (uint8_t *)malloc(total_len)) == NULL) {
        log_fatal("allocation error (%s)", __func__);
        goto out;
    }

    /* now serialize the the access control information */
    offset_ptr = buffer;
    if (bucket0->is_dirty) {
        if (serialize_lockbox(dn, offset_ptr)) {
            log_error("serializing dirnode ACL failed (%s)", fpath);
            goto out;
        }

        // move the pointer ahead
        offset_ptr += dn->header.lockbox_len;
    }

    if (serialize_dirbox(dn, offset_ptr)) {
        log_error("serialization failed");
        goto out;
    }

    /* before we go to the enclave, lets include the acl information
     * as part of bucket0 */
    bucket0->buffer = buffer;
    bucket0->bckt.length += dn->header.lockbox_len;

#ifdef UCAFS_SGX
    ecall_dirnode_crypto(global_eid, &error, dn, UC_ENCRYPT);
    if (error) {
        log_error("enclave encryption failed (%s)", __func__);
        goto out;
    }
#endif

    fwrite(&dn->header, sizeof(dirnode_header_t), 1, fd);

    /* now write the chunk information */
    TAILQ_FOREACH(bucket_entry, &dn->buckets, next_entry)
    {
        // copy the iv, tag and count data
        if (!fwrite(&bucket_entry->bckt, sizeof(dirnode_bucket_t), 1, fd)) {
            log_error("reading bucket failed (%s)", fpath);
            goto out;
        }
    }

    /* write the contents of bucket0 */
    if (bucket0->is_dirty) {
        nbytes = fwrite(bucket0->buffer, 1, bucket0->bckt.length, fd);
        bucket0->is_dirty = false;
        bucket0->buffer = NULL;
    }

    fclose(fd);
    fd = NULL;

    /* now write the buffers in the different files */
    int x = -1;

    TAILQ_FOREACH(bucket_entry, &dn->buckets, next_entry)
    {
        x++;
        if (!bucket_entry->is_dirty) {
            continue;
        }

        /* form the path to the string here */
        path2 = string_and_number(fpath, x);
        /* open the file and save */
        fd2 = fopen(path2, "wb");
        if (fd2 == NULL) {
            log_error("opening '%s' FAILED", path2);
            goto out;
        }

        /* writes the contents of the the bucket */
        nbytes
            = fwrite(bucket_entry->buffer, 1, bucket_entry->bckt.length, fd2);

        fclose(fd2);
        sdsfree(path2);

        fd2 = NULL;
        path2 = NULL;

        bucket_entry->is_dirty = false;
        bucket_entry->buffer = NULL;
    }

    ret = true;
out:
    if (fd) {
        fclose(fd);
    }

    if (fd2) {
        fclose(fd2);
    }

    if (path2) {
        sdsfree(path2);
    }

    if (buffer) {
        free(buffer);
    }

    return ret;
}

bool
dirnode_flush(uc_dirnode_t * dn)
{
    bool ret = dn->dnode_path ? dirnode_write(dn, dn->dnode_path) : false;
    if (ret && dn->mcache) {
        metadata_update_entry(dn->mcache);
    }

    return ret;
}

bool
dirnode_fsync(uc_dirnode_t * dn)
{
    return dirnode_flush(dn);
}

void
dirnode_lockbox_clear(uc_dirnode_t * dn)
{
    acl_list_entry_t * acl_entry;
    acl_list_head_t * acl_list = &dn->lockbox;

    while (!SIMPLEQ_EMPTY(acl_list)) {
        acl_entry = SIMPLEQ_FIRST(acl_list);
        SIMPLEQ_REMOVE_HEAD(acl_list, next_entry);
        free(acl_entry);
    }

    SIMPLEQ_INIT(acl_list);
    dn->header.lockbox_len = 0;
    dn->header.lockbox_count = 0;

    dn->bucket0->is_dirty = true;
}

int
dirnode_lockbox_add(uc_dirnode_t * dn, const char * name, acl_rights_t rights)
{
    int len = strlen(name), total = sizeof(acl_list_entry_t) + len + 1;
    acl_data_t * acl_data;
    acl_list_entry_t * acl_entry = (acl_list_entry_t *)malloc(total);
    if (acl_entry == NULL) {
        return -1;
    }

    acl_data = &acl_entry->acl_data;
    acl_data->rights = rights;
    acl_data->len = len;
    memcpy(acl_data->name, name, len);
    acl_data->name[len] = '\0';

    SIMPLEQ_INSERT_TAIL(&dn->lockbox, acl_entry, next_entry);
    dn->header.lockbox_len += sizeof(acl_data_t) + len + 1;
    dn->header.lockbox_count++;

    dn->bucket0->is_dirty = true;

    return 0;
}

int
dirnode_checkacl(uc_dirnode_t * dn, acl_rights_t rights)
{
    int ret = -1;

#if 0
#ifdef UCAFS_SGX
    ecall_check_rights(global_eid, &ret, &dn->header, &dn->lockbox, rights);
    if (ret) {
        goto out;
    }
#endif
#endif

    ret = 0;
out:
    return ret;
}

shadow_t *
dirnode_add_alias(uc_dirnode_t * dn,
                  const char * name,
                  ucafs_entry_type type,
                  int jrnl,
                  const shadow_t * p_encoded_name,
                  const link_info_t * link_info)
{
    int ret = -1, len, tlen, rec_len;
    shadow_t * shdw_name = NULL;
    dnode_list_entry_t * list_entry = NULL;
    dnode_data_t * de;

    if (type == UC_ANY) {
        return NULL;
    }

    len = strlen(name) + 1, rec_len = sizeof(dnode_dir_payload_t) + len,
    tlen = sizeof(dnode_list_entry_t) + len;

    list_entry = (dnode_list_entry_t *)calloc(1, tlen);
    if (list_entry == NULL) {
        log_fatal("allocation error");
        return NULL;
    }

    de = &list_entry->dnode_data;
    de->info.type = (uint8_t)type;
    de->info.jrnl = (uint8_t)jrnl;
    if (p_encoded_name) {
        memcpy(&de->shadow_name, p_encoded_name, sizeof(shadow_t));
    } else {
        uuid_generate_time_safe(de->shadow_name.bin);
    }

    de->name_len = len;
    memcpy(de->real_name, name, len - 1);

    /* set the link data */
    if (link_info) {
        len = link_info->total_len - sizeof(link_info_t);

        if ((de->target = malloc(len)) == NULL) {
            log_fatal("allocation error");
            goto out;
        }

        memcpy(de->target, link_info->target_link, len);

        de->link_len = len;
        rec_len += de->link_len;
    }

    de->rec_len = rec_len;
    dn->header.dirbox_len += rec_len;
    dn->header.dirbox_count++;

    TAILQ_INSERT_TAIL(&dn->dirbox, list_entry, next_entry);

    if ((shdw_name = (shadow_t *)malloc(sizeof(shadow_t))) == NULL) {
        log_fatal("allocation error");
        return NULL;
    }

    memcpy(shdw_name, &de->shadow_name, sizeof(shadow_t));

    /* insert in the corresponding bucket */
    dirnode_bucket_entry_t *bucket_var, *bucket_entry = NULL;
    TAILQ_FOREACH_REVERSE(bucket_var, &dn->buckets, bucket_list, next_entry)
    {
        if (bucket_var->bckt.count < CONFIG_DIRNODE_BUCKET_CAPACITY) {
            bucket_entry = bucket_var;
            break;
        }
    }

    /* if we found an entry, we can proceed to updating references */
    if (bucket_entry) {
        goto update_refs;
    }

    bucket_entry
        = (dirnode_bucket_entry_t *)calloc(1, sizeof(dirnode_bucket_entry_t));
    if (bucket_entry == NULL) {
        log_fatal("allocation error");
        goto out;
    }

    bucket_entry->freeable = true;
    TAILQ_INSERT_TAIL(&dn->buckets, bucket_entry, next_entry);
    dn->header.bucket_count++;

    dn->bucket_update = true;

update_refs:
    /* update the references */
    bucket_entry->bckt.count++;
    bucket_entry->bckt.length += rec_len;
    bucket_entry->is_dirty = true;

    list_entry->bucket_entry = bucket_entry;

    ret = 0;
out:
    // TODO implement free list_entry
    if (ret) {
        if (shdw_name) {
            free(shdw_name);
            shdw_name = NULL;
        }

        if (list_entry) {
            free_dnode_entry(list_entry);
        }
    }

    return shdw_name;
}

shadow_t *
dirnode_add(uc_dirnode_t * dn,
            const char * name,
            ucafs_entry_type type,
            int jrnl)
{
    return dirnode_add_alias(dn, name, type, jrnl, NULL, NULL);
}

shadow_t *
dirnode_add_link(uc_dirnode_t * dn,
                 const char * link_name,
                 const link_info_t * link_info)
{
    return dirnode_add_alias(dn, link_name, UC_LINK, JRNL_NOOP, NULL, link_info);
}

static inline dnode_list_entry_t *
iterate_by_realname(uc_dirnode_t * dn,
                    const char * realname,
                    ucafs_entry_type * p_type,
                    int * p_journal,
                    link_info_t ** pp_link_info)
{
    dnode_list_entry_t * list_entry;
    dnode_data_t * de;
    link_info_t * link_info;

    int len = strlen(realname) + 1, len1;

    TAILQ_FOREACH(list_entry, &dn->dirbox, next_entry)
    {
        de = &list_entry->dnode_data;

        if (len == de->name_len && memcmp(realname, de->real_name, len) == 0) {
            /* XXX this needs to be deprecated. */
            if (pp_link_info && de->link_len) {
                len1 = de->link_len + sizeof(link_info_t);

                if ((link_info = (link_info_t *)malloc(len1)) == NULL) {
                    log_fatal("allocation error");
                    return NULL;
                }

                link_info->total_len = len1;
                link_info->type
                    = (de->info.type == UC_LINK) ? UC_SOFTLINK : UC_HARDLINK;
                memcpy(link_info->target_link, de->target, de->link_len);
                *pp_link_info = link_info;
            }

            *p_type = de->info.type;
            *p_journal = de->info.jrnl;
            return list_entry;
        }
    }

    return NULL;
}

shadow_t *
dirnode_rm(uc_dirnode_t * dn,
           const char * realname,
           ucafs_entry_type type,
           ucafs_entry_type * p_type,
           int * p_journal,
           link_info_t ** pp_link_info)
{
    shadow_t * result = NULL;
    dnode_list_entry_t * list_entry;
    dnode_data_t * de;
    int len1;

    list_entry
        = iterate_by_realname(dn, realname, p_type, p_journal, pp_link_info);
    if (list_entry == NULL) {
        return NULL;
    }

    de = &list_entry->dnode_data;

    if ((result = (shadow_t *)malloc(sizeof(shadow_t))) == NULL) {
        log_fatal("allocation error");
        return NULL;
    }

    memcpy(result, &de->shadow_name, sizeof(shadow_t));

    /* TODO: delete from the dentry and metadata */
    dn->header.dirbox_count--;
    dn->header.dirbox_len -= de->rec_len;

    /* update the corresponding bucket */
    dirnode_bucket_entry_t * bucket_entry = list_entry->bucket_entry;
    bucket_entry->bckt.count--;
    bucket_entry->bckt.length -= de->rec_len;
    bucket_entry->is_dirty = true;

    // XXX compact here?

    TAILQ_REMOVE(&dn->dirbox, list_entry, next_entry);
    free_dnode_entry(list_entry);

    return result;
out:
    if (result) {
        free(result);
    }

    return NULL;
}

static const inline shadow_t *
__dirnode_raw2enc(uc_dirnode_t * dn,
                  const char * realname,
                  ucafs_entry_type type,
                  ucafs_entry_type * p_type,
                  int * p_journal,
                  const link_info_t ** pp_link_info)
{
    dnode_list_entry_t * list_entry = iterate_by_realname(
        dn, realname, p_type, p_journal, (link_info_t **)pp_link_info);

    return list_entry ? &list_entry->dnode_data.shadow_name : NULL;
}

const shadow_t *
dirnode_raw2enc(uc_dirnode_t * dn,
                const char * realname,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    int journal;
    return __dirnode_raw2enc(dn, realname, type, p_type, &journal, NULL);
}

const shadow_t *
dirnode_traverse(uc_dirnode_t * dn,
                 const char * realname,
                 ucafs_entry_type type,
                 ucafs_entry_type * p_type,
                 int * p_journal,
                 const link_info_t ** pp_link_info)
{
    return __dirnode_raw2enc(dn, realname, type, p_type, p_journal,
                             pp_link_info);
}

const char *
dirnode_enc2raw(uc_dirnode_t * dn,
                const shadow_t * encoded_name,
                ucafs_entry_type type,
                ucafs_entry_type * p_type)
{
    int ret;
    dnode_list_entry_t * list_entry;
    dnode_data_t * de;

    TAILQ_FOREACH(list_entry, &dn->dirbox, next_entry)
    {
        de = &list_entry->dnode_data;

        ret = memcmp(&de->shadow_name, encoded_name, sizeof(shadow_t));
        if (ret == 0) {
            *p_type = de->info.type;
            return de->real_name;
        }
    }

    return NULL;
}

// TODO fix locking
// TODO make sure you add entry to the same bucket
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
    int jrnl;

    *ptr_shadow2_bin = NULL;

    *ptr_shadow1_bin
        = dirnode_rm(dn, oldname, type, &atype, &jrnl, pp_link_info1);
    if (*ptr_shadow1_bin) {
        // it is necessary to return the codename of the existing entry
        // otherwise, we get a lingering file in the AFS server
        //
        // Pass the UNKOWN flag to ensure any copy of the existing file is
        // erased
        shadow2_bin
            = dirnode_rm(dn, newname, UC_ANY, &atype1, &jrnl, pp_link_info2);
        if (shadow2_bin == NULL) {
            shadow2_bin = dirnode_add(dn, newname, atype, jrnl);
        } else {
            // in case the source was a link, its information gets carried over
            shadow2_bin = dirnode_add_alias(dn, newname, atype, jrnl,
                                            shadow2_bin, *pp_link_info1);
        }

        *p_type = atype;
        *ptr_shadow2_bin = shadow2_bin;
        return shadow2_bin == NULL ? -1 : 0;
    }
    return -1;
}

// will generate the serialized version of the dirnode
static int
serialize_dirbox(uc_dirnode_t * dn, uint8_t * buffer)
{
    int len;
    dnode_list_head_t * list_head = &dn->dirbox;
    dnode_list_entry_t * list_entry;
    dnode_data_t * de;
    dirnode_bucket_entry_t *prev_bckt, *curr_bckt = NULL;

    TAILQ_FOREACH(list_entry, list_head, next_entry)
    {
        /* update the bucket pointers */
        prev_bckt = curr_bckt;
        curr_bckt = list_entry->bucket_entry;

        /* if we don't have to serialize the entry, lets skip it */
        if (!curr_bckt->is_dirty) {
            continue;
        }

        if (prev_bckt != curr_bckt) {
            curr_bckt->buffer = buffer;
        }

        de = &list_entry->dnode_data;

        /* lets write the static data */
        len = de->rec_len - de->link_len;
        memcpy(buffer, &de->info, len);
        buffer += len;

        /* write out the link info */
        if ((len = de->link_len)) {
            memcpy(buffer, de->target, len);
            buffer += len;
        }
    }

    return 0;
}

static int
parse_dirbox(uc_dirnode_t * dn, uint8_t * buffer)
{
    int len, ret = -1, entries_left;
    size_t sz;
    dnode_list_head_t * list_head = &dn->dirbox;
    dnode_list_entry_t * list_entry;
    dnode_data_t * de;
    dnode_dir_payload_t * payload = (dnode_dir_payload_t *)buffer;
    dirnode_bucket_entry_t * bucket_entry = TAILQ_FIRST(&dn->buckets);

    entries_left = bucket_entry->bckt.count;
    for (size_t i = 0; i < dn->header.dirbox_count; i++) {
        /* instantiate the list entry */
        sz = sizeof(dnode_list_entry_t)
            + (len = (payload->rec_len - payload->link_len));

        if ((list_entry = (dnode_list_entry_t *)malloc(sz)) == NULL) {
            log_fatal("allocation error");
            goto out;
        }

        de = &list_entry->dnode_data;
        // copy the static data
        memcpy(&de->info, buffer, len);
        buffer += len;

        if ((len = payload->link_len)) {
            if ((de->target = malloc(len)) == NULL) {
                log_fatal("allocation error");
                goto out;
            }

            memcpy(de->target, buffer, len);
            buffer += len;
        } else {
            de->target = NULL;
        }

        TAILQ_INSERT_TAIL(list_head, list_entry, next_entry);

        // move to the next entry
        payload = (dnode_dir_payload_t *)buffer;

        list_entry->bucket_entry = bucket_entry;
        // if we have read all the entries
        if (!(--entries_left)) {
            bucket_entry = TAILQ_NEXT(bucket_entry, next_entry);
            entries_left = bucket_entry ? bucket_entry->bckt.count : 0;
        }
    }

    ret = 0;
out:
    // TODO on error, clear the created entries
    return ret;
}

static int
serialize_lockbox(uc_dirnode_t * dn, uint8_t * buffer)
{
    int len;
    acl_list_entry_t * acl_entry;
    acl_data_t * acl_data;
    uint8_t * buf = buffer;
    acl_list_head_t * acl_list = &dn->lockbox;

    // iterate through the list of all the entries
    SIMPLEQ_FOREACH(acl_entry, acl_list, next_entry)
    {
        acl_data = &acl_entry->acl_data;
        len = sizeof(acl_data_t) + acl_data->len;

        memcpy(buf, acl_data, len);

        buf += len;
    }

    return 0;
}

static int
parse_lockbox(uc_dirnode_t * dn, uint8_t * buffer)
{
    int ret = -1, len, total_len, i, count = dn->header.lockbox_count;
    acl_list_head_t * acl_list = &dn->lockbox;
    acl_data_t *acl_data, *acl_buffer;
    acl_list_entry_t * acl_entry;
    acl_buffer = (acl_data_t *)buffer;

    for (i = 0; i < count; i++) {
        len = acl_buffer->len, total_len = sizeof(acl_data_t) + len;

        acl_entry
            = (acl_list_entry_t *)malloc(sizeof(acl_list_entry_t) + len + 1);
        if (acl_entry == NULL) {
            log_fatal("allocation error");
            goto out;
        }

        /* copy the data from the buffer */
        acl_data = &acl_entry->acl_data;
        memcpy(acl_data, acl_buffer, total_len);

        SIMPLEQ_INSERT_TAIL(acl_list, acl_entry, next_entry);

        acl_buffer = (acl_data_t *)(((caddr_t)acl_buffer) + total_len);
    }

    ret = 0;
out:
    return ret;
}

void
dirnode_rm_from_journal(uc_dirnode_t * dirnode, const shadow_t * shdw)
{
    dnode_list_entry_t * list_entry = NULL;
    dnode_data_t * de;

    TAILQ_FOREACH(list_entry, &dirnode->dirbox, next_entry)
    {
        de = &list_entry->dnode_data;

        if (memcmp(&de->shadow_name, shdw, sizeof(shadow_t)) == 0) {
            de->info.jrnl = JRNL_NOOP;
            break;
        }
    }
}

void
dirnode_set_parent(uc_dirnode_t * dirnode, const uc_dirnode_t * parent)
{
    memcpy(&dirnode->header.parent, &parent->header.uuid, sizeof(shadow_t));
}

const shadow_t *
dirnode_get_parent(uc_dirnode_t * dirnode)
{
    return &dirnode->header.parent;
}

struct metadata_entry *
dirnode_get_metadata(uc_dirnode_t * dn)
{
    return dn->mcache;
}

void
dirnode_set_metadata(uc_dirnode_t * dn, struct metadata_entry * entry)
{
    // XXX get the lock here?
    dn->mcache = entry;
}

void
dirnode_set_dentry(uc_dirnode_t * dirnode, struct uc_dentry * dentry)
{
    dirnode->dentry = dentry;
}

struct uc_dentry *
dirnode_get_dentry(uc_dirnode_t * dirnode)
{
    return dirnode->dentry;
}

void
dirnode_clear_dentry(uc_dirnode_t * dirnode)
{
    dirnode->dentry = NULL;
}

const sds
dirnode_get_fpath(uc_dirnode_t * dirnode)
{
    return dirnode->dnode_path;
}

const shadow_t *
dirnode_get_root(uc_dirnode_t * dirnode)
{
    return &dirnode->header.root;
}

bool
dirnode_equals(uc_dirnode_t * dn1, uc_dirnode_t * dn2)
{
    return memcmp(&dn1->header, &dn2->header, sizeof(dirnode_header_t)) == 0;
}
