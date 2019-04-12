#include "enclave_internal.h"

struct __user {
    nexus_user_flags_t flags;

    nexus_uid_t        user_id;

    struct nexus_uuid  user_uuid;

    pubkey_hash_t      pubkey_hash;

    char               name[NEXUS_MAX_NAMELEN]; // XXX  future 0 byte array impl...
} __attribute__((packed));

struct __table_hdr {
    struct nexus_uuid my_uuid;
    struct nexus_uuid root_uuid;

    uint64_t          total_size;
    uint64_t          user_count;

    nexus_uid_t       auto_increment;

    pubkey_hash_t     pubkey_hash;
} __attribute__((packed));


static void
free_user(void * element)
{
    struct nexus_user * user = (struct nexus_user *)element;
    nexus_free(user->name);
    nexus_free(user);
}

static void
__usertable_set_clean(struct nexus_usertable * usertable)
{
    if (usertable->metadata) {
        __metadata_set_clean(usertable->metadata);
    }
}

static void
__usertable_set_dirty(struct nexus_usertable * usertable)
{
    if (usertable->metadata) {
        __metadata_set_dirty(usertable->metadata);
    }
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
nexus_usertable_set_owner_pubkey(struct nexus_usertable * usertable, char * user_pubkey)
{
    // initialize the owner
    usertable->owner.user_id = NEXUS_ROOT_USER;
    nexus_hash_generate(&usertable->owner.pubkey_hash, user_pubkey, strlen(user_pubkey));
}


struct nexus_usertable *
nexus_usertable_create(struct nexus_uuid * root_uuid, struct nexus_uuid * uuid)
{
    struct nexus_usertable * usertable = nexus_malloc(sizeof(struct nexus_usertable));

    nexus_uuid_copy(root_uuid, &usertable->root_uuid);
    nexus_uuid_copy(uuid, &usertable->my_uuid);

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

    nexus_uuid_copy(&user_buf->user_uuid, &user->user_uuid);

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

    nexus_uuid_copy(&user->user_uuid, &user_buf->user_uuid);

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
    nexus_uuid_copy(&header->root_uuid, &usertable->root_uuid);

    nexus_hash_copy(&header->pubkey_hash, &usertable->owner.pubkey_hash);

    return (buffer + sizeof(struct __table_hdr));
}

int
__parse_usertable(struct nexus_usertable * usertable, uint8_t * buffer, size_t buflen)
{
    uint8_t * input_ptr = __parse_usertable_header(usertable, buffer, buflen);

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
nexus_usertable_from_crypto_buf(struct nexus_crypto_buf * crypto_buffer)
{
    struct nexus_usertable * usertable = nexus_malloc(sizeof(struct nexus_usertable));

    size_t    buflen = 0;
    uint8_t * buffer = nexus_crypto_buf_get(crypto_buffer, &buflen, &usertable->mac);

    if (buffer == NULL) {
        nexus_free(usertable);
        log_error("nexus_crypto_buf_get() FAILED\n");
        return NULL;
    }

    if (__parse_usertable(usertable, buffer, buflen)) {
        nexus_free(usertable);
        log_error("parsing header FAILED\n");
        return NULL;
    }

    return usertable;
}

struct nexus_usertable *
nexus_usertable_load(struct nexus_uuid * uuid, nexus_io_flags_t flags, struct nexus_mac * mac)
{
    struct nexus_usertable  * usertable     = NULL;

    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t * buffer = NULL;

    int ret = -1;


    crypto_buffer = nexus_crypto_buf_create(uuid, flags);

    if (crypto_buffer == NULL) {
        log_error("nexus_crypto_buf_create FAILED\n");
        return NULL;
    }

    usertable = nexus_usertable_from_crypto_buf(crypto_buffer);

    nexus_crypto_buf_free(crypto_buffer);

    return usertable;
}

static uint8_t *
__serialize_usertable_header(struct nexus_usertable * usertable, uint8_t * buffer)
{
    struct __table_hdr * header = (struct __table_hdr *)buffer;

    memset(header, 0, sizeof(struct __table_hdr));

    header->auto_increment = usertable->auto_increment;
    header->user_count     = usertable->user_count;
    header->total_size     = usertable->total_size;

    nexus_uuid_copy(&usertable->my_uuid, &header->my_uuid);
    nexus_uuid_copy(&usertable->root_uuid, &header->root_uuid);

    nexus_hash_copy(&usertable->owner.pubkey_hash, &header->pubkey_hash);

    return (buffer + sizeof(struct __table_hdr));
}

static int
__serialize_usertable(struct nexus_usertable * usertable, uint8_t * buffer)
{
    uint8_t * output_ptr = __serialize_usertable_header(usertable, buffer);

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
nexus_usertable_store(struct nexus_usertable * usertable, uint32_t version, struct nexus_mac * mac)
{
    struct nexus_crypto_buf * crypto_buffer = NULL;

    uint8_t                 * output_buffer = NULL;

    size_t                    buffer_size   = nexus_usertable_buflen(usertable);


    crypto_buffer = nexus_crypto_buf_new(buffer_size, version, &usertable->my_uuid);

    if (crypto_buffer == NULL) {
        log_error("could not initialize crypto buffer\n");
        return -1;
    }

    // XXX: this pattern is common amongst all metadata. At some point, we will
    // have to refactor this.
    output_buffer = nexus_crypto_buf_get(crypto_buffer, &buffer_size, NULL);

    if (output_buffer == NULL) {
        log_error("could not get the crypto_buffer buffer\n");
        goto out_err;
    }

    if (__serialize_usertable(usertable, output_buffer)) {
        log_error("__serialize_usertable() FAILED\n");
        goto out_err;
    }

    if (nexus_crypto_buf_put(crypto_buffer, &usertable->mac)) {
        log_error("nexus_crypto_buf_put FAILED\n");
        goto out_err;
    }

    if (mac) {
        nexus_mac_copy(mac, &usertable->mac);
    }

    nexus_crypto_buf_free(crypto_buffer);

    return 0;
out_err:
    nexus_crypto_buf_free(crypto_buffer);

    return -1;
}


struct nexus_list_iterator *
__nexus_usertable_get_iterator(struct nexus_usertable * usertable)
{
    return list_iterator_new(&usertable->userlist);
}

static struct nexus_list_iterator *
__usertable_find_name(struct nexus_usertable * usertable, char * name)
{
    struct nexus_list_iterator * iter = NULL;

    iter = list_iterator_new(&usertable->userlist);

    while (list_iterator_is_valid(iter)) {
        struct nexus_user * user = list_iterator_get(iter);

        if (strncmp(user->name, name, NEXUS_MAX_NAMELEN) == 0) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);
    return NULL;
}

static struct nexus_list_iterator *
__usertable_find_pubkey_hash(struct nexus_usertable * usertable, pubkey_hash_t * pubkey_hash)
{
    struct nexus_list_iterator * iter = NULL;

    iter = list_iterator_new(&usertable->userlist);

    while (list_iterator_is_valid(iter)) {
        struct nexus_user * user = list_iterator_get(iter);

        if (nexus_hash_compare(&user->pubkey_hash, pubkey_hash) == 0) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);
    return NULL;
}

static struct nexus_list_iterator *
__usertable_find_uuid(struct nexus_usertable * usertable, struct nexus_uuid * uuid)
{
    struct nexus_list_iterator * iter = NULL;

    iter = list_iterator_new(&usertable->userlist);

    while (list_iterator_is_valid(iter)) {
        struct nexus_user * user = list_iterator_get(iter);

        if (nexus_uuid_compare(&user->user_uuid, uuid) == 0) {
            return iter;
        }

        list_iterator_next(iter);
    }

    list_iterator_free(iter);
    return NULL;
}

struct nexus_user *
nexus_usertable_find_name(struct nexus_usertable * usertable, char * name)
{
    struct nexus_user * user = NULL;

    struct nexus_list_iterator * iter = NULL;

    iter = __usertable_find_name(usertable, name);

    if (iter == NULL) {
        return NULL;
    }


    user = list_iterator_get(iter);

    list_iterator_free(iter);

    return user;
}

struct nexus_user *
nexus_usertable_find_pubkey_hash(struct nexus_usertable * usertable, pubkey_hash_t * pubkey_hash)
{
    struct nexus_user * user = NULL;

    struct nexus_list_iterator * iter = NULL;

    // let's see if it matches the owner
    if (nexus_hash_compare(&usertable->owner.pubkey_hash, pubkey_hash) == 0) {
        return &usertable->owner;
    }

    iter = __usertable_find_pubkey_hash(usertable, pubkey_hash);

    if (iter == NULL) {
        return NULL;
    }


    user = list_iterator_get(iter);

    list_iterator_free(iter);

    return user;
}

struct nexus_user *
nexus_usertable_find_pubkey(struct nexus_usertable * usertable, char * pubkey_str)
{
    pubkey_hash_t pubkey_hash;

    if (crypto_hash_pubkey(pubkey_str, &pubkey_hash)) {
        log_error("could not hash pubkey\n");
        return NULL;
    }

    return nexus_usertable_find_pubkey_hash(usertable, &pubkey_hash);
}

struct nexus_user *
nexus_usertable_find_uuid(struct nexus_usertable * usertable, struct nexus_uuid * uuid)
{
    struct nexus_list_iterator * iter = __usertable_find_uuid(usertable, uuid);

    struct nexus_user * user = NULL;

    if (iter == NULL) {
        return NULL;
    }

    user = list_iterator_get(iter);

    list_iterator_free(iter);

    return user;
}


int
nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str)
{
    if (__nexus_usertable_add(usertable, name, pubkey_str) == NULL) {
        return -1;
    }

    return 0;
}

struct nexus_user *
__nexus_usertable_add(struct nexus_usertable * usertable, char * name, char * pubkey_str)
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
            return NULL;
        }


        existing_user = nexus_usertable_find_pubkey_hash(usertable, &pubkey_hash);

        if (existing_user != NULL) {
            log_error("user already with specified public key already in database\n");
            return NULL;
        }
    }

    usertable->auto_increment += 1;
    usertable->user_count     += 1;

    new_user = nexus_malloc(sizeof(struct nexus_user));

    new_user->user_id = usertable->auto_increment;
    new_user->name = strndup(name, NEXUS_MAX_NAMELEN);

    nexus_uuid_gen(&new_user->user_uuid);

    nexus_hash_copy(&pubkey_hash, &new_user->pubkey_hash);

    nexus_list_append(userlist, new_user);

    __usertable_set_dirty(usertable);

    return new_user;
}

int
nexus_usertable_remove_username(struct nexus_usertable * usertable,
                                char                   * username,
                                struct nexus_uuid      * uuid)
{
    struct nexus_list_iterator * iter = __usertable_find_name(usertable, username);

    if (iter == NULL) {
        return -1;
    }

    struct nexus_user * user = list_iterator_get(iter);

    nexus_uuid_copy(&user->user_uuid, uuid);

    list_iterator_del(iter);
    list_iterator_free(iter);

    usertable->user_count     -= 1;

    __usertable_set_dirty(usertable);

    return 0;
}

int
nexus_usertable_remove_pubkey(struct nexus_usertable * usertable,
                              char                   * pubkey_str,
                              struct nexus_uuid      * uuid)
{
    pubkey_hash_t                pubkey_hash;

    struct nexus_list_iterator * iter = NULL;

    if (crypto_hash_pubkey(pubkey_str, &pubkey_hash)) {
        log_error("could not hash pubkey\n");
        return -1;
    }

    iter = __usertable_find_pubkey_hash(usertable, &pubkey_hash);

    if (iter == NULL) {
        return -1;
    }

    struct nexus_user * user = list_iterator_get(iter);

    nexus_uuid_copy(&user->user_uuid, uuid);

    list_iterator_del(iter);
    list_iterator_free(iter);

    usertable->user_count     -= 1;

    __usertable_set_dirty(usertable);

    return 0;
}
