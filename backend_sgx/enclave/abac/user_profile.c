#include "user_profile.h"
#include "attribute_store.h"
#include "attribute_table.h"


struct __user_profile_hdr {
    struct nexus_uuid      my_uuid;
    struct nexus_uuid      root_uuid;
} __attribute__((packed));



static void
__user_profile_set_dirty(struct user_profile * user_profile)
{
    if (user_profile->metadata) {
        __metadata_set_dirty(user_profile->metadata);
    }
}


/// --[[ create/destroy

struct user_profile *
user_profile_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct user_profile * user_profile = nexus_malloc(sizeof(struct user_profile));

    user_profile->attribute_table = attribute_table_create();

    nexus_uuid_copy(root_uuid, &user_profile->root_uuid);
    nexus_uuid_copy(uuid, &user_profile->my_uuid);

    return user_profile;
}

void
user_profile_free(struct user_profile * user_profile)
{
    if (user_profile->attribute_table) {
        attribute_table_free(user_profile->attribute_table);
    }

    nexus_free(user_profile);
}

/// create/destroy ]]--


/// --[[ load/store

struct user_profile *
user_profile_from_buffer(uint8_t * buffer, size_t buflen)
{
    struct user_profile * user_profile = nexus_malloc(sizeof(struct user_profile));

    if (buflen < sizeof(struct __user_profile_hdr)) {
        log_error("user_profile buffer is too small\n");
        nexus_free(user_profile);
        return NULL;
    }

    // parse the header
    {
        struct __user_profile_hdr * header = (struct __user_profile_hdr *)buffer;

        nexus_uuid_copy(&header->root_uuid, &user_profile->root_uuid);
        nexus_uuid_copy(&header->my_uuid, &user_profile->my_uuid);
    }

    buffer += sizeof(struct __user_profile_hdr);
    buflen -= sizeof(struct __user_profile_hdr);

    user_profile->attribute_table = attribute_table_from_buffer(buffer, buflen);

    if (user_profile->attribute_table == NULL) {
        log_error("attribute_table_from_buffer() FAILED\n");
        nexus_free(user_profile);
        return NULL;
    }

    return user_profile;
}

struct user_profile *
user_profile_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    return user_profile_from_buffer(buffer, buflen);
}

static size_t
__get_user_profile_size(struct user_profile * user_profile)
{
    return sizeof(struct __user_profile_hdr)
           + attribute_table_get_size(user_profile->attribute_table);
}

static int
__user_profile_serialize(struct user_profile     * user_profile,
                         struct nexus_crypto_buf * crypto_buffer)
{
    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, NULL);

    if (buffer == NULL) {
        log_error("nexus_crypto_buf_get() FAILED\n");
        return -1;
    }

    // write the header
    {
         struct __user_profile_hdr * header = (struct __user_profile_hdr *)buffer;

         nexus_uuid_copy(&user_profile->my_uuid, &header->my_uuid);
         nexus_uuid_copy(&user_profile->root_uuid, &header->root_uuid);
    }

    buffer += sizeof(struct __user_profile_hdr);
    buflen -= sizeof(struct __user_profile_hdr);

    // write the attribute table
    if (attribute_table_store(user_profile->attribute_table, buffer, buflen)) {
        log_error("attribute_table_store() FAILED\n");
        return -1;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &user_profile->mac)) {
        log_error("nexus_crypto_buf_put FAILED\n");
        return -1;
    }

    return 0;
}

int
user_profile_store(struct user_profile * user_profile, uint32_t version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen = __get_user_profile_size(user_profile);


    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, version, &user_profile->my_uuid);

    if (crypto_buffer == NULL) {
        log_error("nexus_crypto_buf_new() FAILED\n");
        return -1;
    }

    if (__user_profile_serialize(user_profile, crypto_buffer)) {
        log_error("__user_profile_serialize() FAILED\n");
        goto out_err;
    }

    if (mac) {
        nexus_mac_copy(&user_profile->mac, mac);
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;

out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}

/// load/store ]]--


int
user_profile_grant_attribute(struct user_profile * user_profile, char * name, char * value)
{
    struct attribute_term * attribute_term = NULL;

    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_term = (struct attribute_term *)attribute_store_find_name(attribute_store, name);

    if (attribute_term == NULL) {
        log_error("could not find attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_term->type != USER_ATTRIBUTE_TYPE) {
        log_error("attribute type for (%s) is not user\n", attribute_term->name);
        return -1;
    }

    if (attribute_table_add(user_profile->attribute_table, &attribute_term->uuid, value)) {
        log_error("attribute_table_add() FAILED\n");
        return -1;
    }

    __user_profile_set_dirty(user_profile);

    return 0;
}

int
user_profile_revoke_attribute(struct user_profile * user_profile, char * name)
{
    struct attribute_term * attribute_term = NULL;

    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get global attribute store\n");
        return -1;
    }

    attribute_term = (struct attribute_term *)attribute_store_find_name(attribute_store, name);

    if (attribute_term == NULL) {
        log_error("could not find attribute (%s) in store\n", name);
        return -1;
    }

    if (attribute_table_del(user_profile->attribute_table, &attribute_term->uuid)) {
        log_error("attribute_table_del() FAILED\n");
        return -1;
    }

    __user_profile_set_dirty(user_profile);

    return 0;
}

int
UNSAFE_user_profile_attribute_ls(struct user_profile       * user_profile,
                                 struct nxs_attribute_pair * attribute_pair_array,
                                 size_t                      attribute_pair_capacity,
                                 size_t                      offset,
                                 size_t                    * result_count,
                                 size_t                    * total_count)
{
    struct attribute_store * attribute_store = abac_acquire_attribute_store(NEXUS_FREAD);

    if (attribute_store == NULL) {
        log_error("could not get attribute_store\n");
        return -1;
    }

    return UNSAFE_attribute_table_ls(user_profile->attribute_table,
                                     attribute_store,
                                     attribute_pair_array,
                                     attribute_pair_capacity,
                                     offset,
                                     result_count,
                                     total_count);
}
