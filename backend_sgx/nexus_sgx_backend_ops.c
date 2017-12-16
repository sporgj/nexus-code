#include "nexus_sgx_backend.h"


int
backend_volume_create(struct uuid *      supernode_uuid,
                      struct uuid *      root_uuid,
                      const char *       publickey_fpath,
                      struct supernode * supernode_out,
                      struct dirnode *   root_dirnode_out,
                      struct volumekey * volume_out)
{
    int    ret        = -1;
    int    err        = -1;
    size_t pubkey_len = 0;
    char * pubkey_buf = NULL;

    ret = mbedtls_pk_load_file(
        publickey_fpath, (uint8_t **)&pubkey_buf, &pubkey_len);

    if (ret != 0) {
        log_error("Could not load key: %s", publickey_fpath);
        return -1;
    }

    err = ecall_create_volume(global_enclave_id,
                              &ret,
                              supernode_uuid,
                              root_uuid,
                              pubkey_buf,
                              pubkey_len,
                              supernode_out,
                              root_dirnode_out,
                              volume_out);

    free(pubkey_buf);

    if (err || ret) {
        log_error("ecall_create_volume FAILED ret=%d", ret);
        return -1;
    }

    return 0;
}


int
backend_dirnode_new(struct uuid *     dirnode_uuid,
                    struct uuid *     root_uuid,
                    struct dirnode ** p_dirnode)
{
    int              ret     = -1;
    int              err     = -1;
    struct dirnode * dirnode = NULL;

    dirnode = (struct dirnode *)calloc(1, sizeof(struct dirnode));
    if (dirnode == NULL) {
        log_error("allocation error");
        return -1;
    }

    err = ecall_dirnode_new(
        global_enclave_id, &ret, dirnode_uuid, root_uuid, dirnode);

    if (err || ret) {
        free(dirnode);
        log_error("ecall_dirnode_new() FAILED");
        return -1;
    }

    *p_dirnode = dirnode;

    return 0;
}

int
backend_dirnode_add(struct dirnode *    parent_dirnode,
                    struct uuid *       uuid,
                    const char *        fname,
                    nexus_fs_obj_type_t type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_add(
        global_enclave_id, &ret, parent_dirnode, uuid, fname, type);

    if (err || ret) {
        log_error("ecall_dirnode_add FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_find_by_uuid(struct dirnode *      dirnode,
                             struct uuid *         uuid,
                             char **               p_fname,
                             nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_find_by_uuid(
        global_enclave_id, &ret, dirnode, uuid, p_fname, p_type);

    if (err || ret) {
        // log_error(
        //    "ecall_dirnode_find_by_uuid FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_find_by_name(struct dirnode *      dirnode,
                             char *                fname,
                             struct uuid *         uuid,
                             nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_find_by_name(
        global_enclave_id, &ret, dirnode, fname, uuid, p_type);

    if (err || ret) {
        // log_error(
        ///    "ecall_dirnode_find_by_name FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_remove(struct dirnode *      dirnode,
                       char *                fname,
                       struct uuid *         uuid,
                       nexus_fs_obj_type_t * p_type)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_remove(
        global_enclave_id, &ret, dirnode, fname, uuid, p_type);

    if (err || ret) {
        log_error("ecall_dirnode_remove FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}

int
backend_dirnode_serialize(struct dirnode *  dirnode,
                          struct dirnode ** p_sealed_dirnode)
{
    int ret = -1;
    int err = -1;

    err = ecall_dirnode_serialize(
        global_enclave_id, &ret, dirnode, p_sealed_dirnode);

    if (err || ret) {
        log_error("ecall_dirnode_serialize FAILED (err=%d, ret=%d)", err, ret);
        return -1;
    }

    return 0;
}
