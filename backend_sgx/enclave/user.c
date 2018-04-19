#include "enclave_internal.h"

struct __user {
    nexus_user_flags_t flags;

    nexus_uid_t        user_id;

    pubkey_hash_t      pubkey_hash;

    char               name[NEXUS_MAX_NAMELEN]; // XXX  future 0 byte array impl...
} __attribute__((packed));

// my initial iteration has the usertable embedded inside the supernode (which is
// practically empty at this point).
struct __table_hdr {
    struct nexus_uuid my_uuid;

    uint64_t          total_size;
    uint64_t          user_count;

    nexus_uid_t       auto_increment;

    pubkey_hash_t     pubkey_hash;
} __attribute__((packed));


struct nexus_usertable {
    uint32_t version;

    uint64_t auto_increment;
    uint64_t user_count;
    uint64_t total_size;

    struct nexus_uuid my_uuid;

    struct nexus_user owner;

    struct nexus_list userlist;
};


static void
free_user(void * element)
{
    struct nexus_user * user = (struct nexus_user *)element;
    nexus_free(user->name);
    nexus_free(user);
}

static void
init_userlist(struct nexus_usertable * usertable)
{
    nexus_list_init(&usertable->userlist);
    nexus_list_set_deallocator(&usertable->userlist, free_user);
}

size_t
nexus_usertable_buflen(struct nexus_usertable * usertable)
{
    return sizeof(struct __table_hdr) + (usertable->user_count * sizeof(struct __user));
}

void
nexus_usertable_copy_uuid(struct nexus_usertable * usertable, struct nexus_uuid * dest_uuid)
{
    nexus_uuid_copy(&usertable->my_uuid, dest_uuid);
}

struct nexus_usertable *
nexus_usertable_create(char * user_pubkey)
{
    struct nexus_usertable * usertable = NULL;

    struct nexus_user * owner = NULL;


    usertable = nexus_malloc(sizeof(struct nexus_usertable));

    nexus_uuid_gen(&usertable->my_uuid);


    // initialize the owner
    owner = &usertable->owner;

    owner->user_id = 0;
    nexus_hash_generate(&owner->pubkey_hash, user_pubkey, strlen(user_pubkey));


    init_userlist(usertable);

    return usertable;
}


void
nexus_usertable_free(struct nexus_usertable * usertable)
{
    if (usertable == NULL) {
        return;
    }

    nexus_list_destroy(&usertable->userlist);
    nexus_free(usertable);
}

struct nexus_user *
__read_user_from_buf(uint8_t * buf)
{
    struct nexus_user * user = NULL;

    struct __user * user_buf = (struct __user*)buf;

    user = nexus_malloc(sizeof(struct nexus_user));

    user->flags   = user_buf->flags;
    user->user_id = user_buf->user_id;

    nexus_hash_copy(&user_buf->pubkey_hash, &user->pubkey_hash);

    user->name = strndup(user_buf->name, NEXUS_MAX_NAMELEN);

    return user;
}

uint8_t *
__write_user_to_buf(struct nexus_user * user, uint8_t * buf)
{
    struct __user * user_buf = (struct __user*)buf;

    memset(user_buf, 0, sizeof(struct __user));

    user_buf->flags   = user->flags;
    user_buf->user_id = user->user_id;

    nexus_hash_copy(&user->pubkey_hash, &user_buf->pubkey_hash);

    strncpy(user_buf->name, user->name, NEXUS_MAX_NAMELEN);

    return (buf + sizeof(struct __user));
}

static uint8_t *
__parse_usertable_header(struct nexus_usertable * usertable, uint8_t * buffer, size_t buflen)
{
    struct __table_hdr * header = NULL;

    if (buflen < sizeof(struct __table_hdr)) {
        log_error("the buffer is too small for a usertable\n");
        return NULL;
    }

    header = (struct __table_hdr *)buffer;

    usertable->auto_increment = header->auto_increment;
    usertable->user_count     = header->user_count;
    usertable->total_size     = header->total_size;

    nexus_uuid_copy(&header->my_uuid, &usertable->my_uuid);

    nexus_hash_copy(&header->pubkey_hash, &usertable->owner.pubkey_hash);

    return (buffer + sizeof(struct __table_hdr));
}

int
__parse_usertable(struct nexus_usertable * usertable, uint8_t * buffer, size_t buflen)
{
    uint8_t * input_ptr = NULL;

    /// parse the buffers here
    input_ptr = __parse_usertable_header(usertable, buffer, buflen);

    if (input_ptr == NULL) {
        log_error("parsing the header failed\n");
        return -1;
    }

    init_userlist(usertable);

    for (size_t i = 0; i < usertable->user_count; i++) {
        size_t size = sizeof(struct __user);

        struct nexus_user * user = __read_user_from_buf(input_ptr);

        nexus_list_append(&usertable->userlist, user);

        input_ptr += size;
    }

    return 0;
}

struct nexus_usertable *
nexus_usertable_load(struct nexus_uuid * uuid, nexus_io_mode_t mode, struct nexus_mac * mac)
{
    struct nexus_usertable * usertable = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * buffer = NULL;
    size_t    buflen = 0;

    int ret = -1;


    crypto_buffer = nexus_crypto_buf_create(uuid, mode);

    if (crypto_buffer == NULL) {
        log_error("buffer_layer_read_datastore FAILED\n");
        return NULL;
    }

    buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, mac);

    if (buffer == NULL) {
        nexus_crypto_buf_free(crypto_buffer);

        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }


    usertable = nexus_malloc(sizeof(struct nexus_usertable));

    ret = __parse_usertable(usertable, buffer, buflen);

    nexus_crypto_buf_free(crypto_buffer);

    if (ret != 0) {
        nexus_free(usertable);

        log_error("parsing header FAILED\n");

        return NULL;
    }

    usertable->version = nexus_crypto_buf_version(crypto_buffer);

    return usertable;
}

static uint8_t *
__serialize_usertable_header(struct nexus_usertable * usertable, uint8_t * buffer)
{
    struct __table_hdr * header = NULL;

    header = (struct __table_hdr *)buffer;

    memset(header, 0, sizeof(struct __table_hdr));

    header->auto_increment = usertable->auto_increment;
    header->user_count     = usertable->user_count;
    header->total_size     = usertable->total_size;

    nexus_uuid_copy(&usertable->my_uuid, &header->my_uuid);

    nexus_hash_copy(&usertable->owner.pubkey_hash, &header->pubkey_hash);

    return (buffer + sizeof(struct __table_hdr));
}

static int
__serialize_usertable(struct nexus_usertable * usertable, uint8_t * buffer)
{
    uint8_t * output_ptr = NULL;

    output_ptr = __serialize_usertable_header(usertable, buffer);

    if (output_ptr == NULL) {
        log_error("__serialize_usertable_header FAILED\n");
        return -1;
    }

    {
        struct nexus_list_iterator * iter = NULL;

        iter = list_iterator_new(&usertable->userlist);

        while (list_iterator_is_valid(iter)) {
            struct nexus_user * user = list_iterator_get(iter);

            output_ptr = __write_user_to_buf(user, output_ptr);

            list_iterator_next(iter);
        }

        list_iterator_free(iter);
    }

    return 0;
}

int
nexus_usertable_store(struct nexus_usertable * usertable, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    size_t serialized_buflen = 0;

    int ret = -1;


    serialized_buflen = nexus_usertable_buflen(usertable);

    crypto_buffer = nexus_crypto_buf_new(serialized_buflen, usertable->version, &usertable->my_uuid);

    if (!crypto_buffer) {
        log_error("could not initialize crypto buffer\n");
        goto out;
    }

    // XXX: this pattern is common amongst all metadata. At some point, we will
    // have to refactor this.
    {
        uint8_t * output_buffer = NULL;

        size_t    buffer_size   = 0;


        output_buffer = nexus_crypto_buf_get(crypto_buffer, &buffer_size, NULL);
        if (output_buffer == NULL) {
            log_error("could not get the crypto_buffer buffer\n");
            goto out;
        }

        ret = __serialize_usertable(usertable, output_buffer);
        if (ret != 0) {
            log_error("dirnode_serialize() FAILED\n");
            goto out;
        }

        ret = nexus_crypto_buf_put(crypto_buffer, mac);
        if (ret != 0) {
            log_error("nexus_crypto_buf_put FAILED\n");
            goto out;
        }
    }

    // flush the buffer to the backend
    ret = nexus_crypto_buf_flush(crypto_buffer);

    if (ret) {
        log_error("metadata_write FAILED\n");
        goto out;
    }


    usertable->version += 1;

    ret = 0;
out:
    if (crypto_buffer) {
        nexus_crypto_buf_free(crypto_buffer);
    }

    return ret;
}

struct nexus_user *
nexus_usertable_find_name(struct nexus_usertable * usertable, char * name)
{
    struct nexus_list_iterator * iter = NULL;

    iter = list_iterator_new(&usertable->userlist);

    while (list_iterator_is_valid(iter)) {
        struct nexus_user * user = list_iterator_get(iter);

        if (strncmp(user->name, name, NEXUS_MAX_NAMELEN) == 0) {
            list_iterator_free(iter);
            return user;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return NULL;
}

struct nexus_user *
nexus_usertable_find_pubkey(struct nexus_usertable * usertable, pubkey_hash_t * pubkey_hash)
{
    struct nexus_list_iterator * iter = NULL;

    // let's see if it matches the owner
    if (nexus_hash_compare(&usertable->owner.pubkey_hash, pubkey_hash) == 0) {
        return &usertable->owner;
    }

    iter = list_iterator_new(&usertable->userlist);

    while (list_iterator_is_valid(iter)) {
        struct nexus_user * user = list_iterator_get(iter);

        if (nexus_hash_compare(&user->pubkey_hash, pubkey_hash) == 0) {
            list_iterator_free(iter);
            return user;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);

    return NULL;
}

int
nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str)
{
    struct nexus_user * new_user = NULL;

    struct nexus_list * userlist = &usertable->userlist;

    pubkey_hash_t pubkey_hash;


    nexus_hash_generate(&pubkey_hash, pubkey_str, strlen(pubkey_str));

    // check if anyone has the same name or public key
    {
        struct nexus_user * existing_user = NULL;

        existing_user = nexus_usertable_find_name(usertable, name);

        if (existing_user != NULL) {
            log_error("user '%s' already in database\n", name);
            return -1;
        }


        existing_user = nexus_usertable_find_pubkey(usertable, &pubkey_hash);

        if (existing_user != NULL) {
            log_error("user already with specified public key already in database\n");
            return -1;
        }
    }

    usertable->auto_increment += 1;
    usertable->user_count     += 1;

    new_user = nexus_malloc(sizeof(struct nexus_user));

    new_user->user_id = usertable->auto_increment;
    new_user->name = strndup(name, NEXUS_MAX_NAMELEN);

    nexus_hash_copy(&pubkey_hash, &new_user->pubkey_hash);

    nexus_list_append(userlist, new_user);

    return 0;
}
