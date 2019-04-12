#include "../enclave_internal.h"

void
UNSAFE_export_user_buffer(struct nexus_user * user, struct nxs_user_buffer * user_buffer)
{
    memcpy(user_buffer->name, user->name, NEXUS_MAX_NAMELEN);
    memcpy(user_buffer->pubkey_hash, &user->pubkey_hash, NEXUS_PUBKEY_HASHLEN);
}

int
ecall_user_add(char * username_IN, char * user_pubkey_IN)
{
    struct nexus_usertable * global_usertable = NULL;

    struct nexus_user * new_user = NULL;

    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not have sufficient permissions\n");
        return -1;
    }

    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FRDWR);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }

    new_user = __nexus_usertable_add(global_usertable, username_IN, user_pubkey_IN);
    if (new_user == NULL) {
        log_error("could not add public key to the user table\n");
        goto out;
    }

    if (abac_create_user_profile(&new_user->user_uuid)) {
        log_error("abac_global_create_user_profile() FAILED\n");
        goto out;
    }

    if (nexus_vfs_flush_user_table()) {
        log_error("could not store usertable\n");
        goto out;
    }

    nexus_vfs_release_user_table();

    return 0;
out:
    nexus_vfs_release_user_table();

    return -1;
}

int
ecall_user_remove_username(char * username_IN)
{
    struct nexus_usertable * global_usertable = NULL;

    struct nexus_uuid user_uuid;

    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not sufficient permissions\n");
        return -1;
    }

    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FRDWR);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }

    if (nexus_usertable_remove_username(global_usertable, username_IN, &user_uuid)) {
        log_error("could not remove username from table\n");
        return -1;
    }

    if (nexus_vfs_flush_user_table()) {
        log_error("could not store usertable\n");
        goto err;
    }

    if (abac_del_user_profile(&user_uuid)) {
        log_error("abac_global_create_user_profile() FAILED\n");
        goto err;
    }

    nexus_vfs_release_user_table();

    return 0;
err:
    nexus_vfs_release_user_table();

    return -1;
}

int
ecall_user_remove_pubkey(char * pubkey_str_IN)
{
    struct nexus_usertable * global_usertable = NULL;

    struct nexus_uuid user_uuid;

    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not sufficient permissions\n");
        return -1;
    }

    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FRDWR);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }

    if (nexus_usertable_remove_pubkey(global_usertable, pubkey_str_IN, &user_uuid)) {
        log_error("could remove pubkey from usertable\n");
        goto err;
    }

    if (nexus_vfs_flush_user_table()) {
        log_error("could not store usertable\n");
        goto err;
    }

    if (abac_del_user_profile(&user_uuid)) {
        log_error("abac_global_create_user_profile() FAILED\n");
        goto err;
    }

    nexus_vfs_release_user_table();

    return 0;
err:
    nexus_vfs_release_user_table();

    return -1;
}


int
ecall_user_find_username(char * username_IN, struct nxs_user_buffer * user_buffer_out)
{
    struct nexus_usertable * global_usertable = NULL;

    struct nexus_user      * user             = NULL;


    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not sufficient permissions\n");
        return -1;
    }


    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }


    user = nexus_usertable_find_name(global_usertable, username_IN);

    if (user == NULL) {
        log_error("find username in usertable\n");
        goto err;
    }


    UNSAFE_export_user_buffer(user, user_buffer_out);

    nexus_vfs_release_user_table();

    return 0;
err:
    nexus_vfs_release_user_table();

    return -1;
}

int
ecall_user_find_pubkey(char * pubkey_IN, struct nxs_user_buffer * user_buffer_out)
{
    struct nexus_usertable * global_usertable = NULL;

    struct nexus_user      * user             = NULL;


    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not sufficient permissions\n");
        return -1;
    }


    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }


    user = nexus_usertable_find_pubkey(global_usertable, pubkey_IN);

    if (user == NULL) {
        log_error("find pubkey in usertable\n");
        goto err;
    }


    UNSAFE_export_user_buffer(user, user_buffer_out);

    nexus_vfs_release_user_table();

    return 0;
err:
    nexus_vfs_release_user_table();

    return -1;
}

static int
UNSAFE_dump_user_buffer(struct nexus_usertable   * usertable,
                        struct nxs_user_buffer   * user_buffer_array,
                        size_t                     user_buffer_count,
                        size_t                     offset,
                        size_t                   * total_count,
                        size_t                   * result_count)
{
    struct nexus_list_iterator * iter = NULL;

    int pos = 0;


    if (offset > usertable->user_count) {
        log_error("offset is out of range\n");
        return -1;
    }

    iter = __nexus_usertable_get_iterator(usertable);


    while (offset--) {
        list_iterator_next(iter);
    }


    for (; pos < user_buffer_count && list_iterator_is_valid(iter); pos++) {
        struct nexus_user * user = list_iterator_get(iter);

        UNSAFE_export_user_buffer(user, &user_buffer_array[pos]);

        list_iterator_next(iter);
    }

    *total_count = usertable->user_count;
    *result_count = pos;

    list_iterator_free(iter);

    return 0;
}

int
ecall_user_ls(struct nxs_user_buffer   * user_buffer_array_in,
              size_t                     user_buffer_count_IN,
              size_t                     offset_IN,
              size_t                   * total_count_out,
              size_t                   * result_count_out)
{
    struct nexus_usertable * global_usertable = NULL;

    int                      ret              = -1;


    if (!nexus_enclave_is_current_user_owner()) {
        log_error("you do not sufficient permissions\n");
        return -1;
    }


    global_usertable = nexus_vfs_acquire_user_table(NEXUS_FREAD);

    if (global_usertable == NULL) {
        log_error("could not acquire global supernode\n");
        return -1;
    }

    ret = UNSAFE_dump_user_buffer(global_usertable,
                                  user_buffer_array_in,
                                  user_buffer_count_IN,
                                  offset_IN,
                                  total_count_out,
                                  result_count_out);

    if (ret != 0) {
        log_error("could not dump user buffer\n");
        goto err;
    }


    nexus_vfs_release_user_table();

    return 0;
err:
    nexus_vfs_release_user_table();

    return -1;
}
