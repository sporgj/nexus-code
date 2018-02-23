#include "internal.h"

#if 0
static void
split_path(char * filepath, char ** dirpath, char ** filename)
{
    char * fname = NULL;

    fname = strrchr(filepath, '/');

    if (fname == NULL) {
        *filename = filepath;
        *dirpath = ".";
    } else {
        *filename = fname;
        *dirpath = filepath;
    }
}
#endif

int
sgx_backend_fs_create(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      nexus_dirent_type_t    type,
                      char                ** nexus_name,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_create(sgx_backend->enclave_id, &ret, dirpath, plain_name, type, &uuid);

    if (err || ret) {
        log_error("ecall_fs_create() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *nexus_name = nexus_uuid_to_alt64(&uuid);

    return 0;
}

int
sgx_backend_fs_remove(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      char                ** nexus_name,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_remove(sgx_backend->enclave_id, &ret, dirpath, plain_name, &uuid);

    if (err || ret) {
        log_error("ecall_fs_remove() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *nexus_name = nexus_uuid_to_alt64(&uuid);

    return 0;
}

int
sgx_backend_fs_lookup(struct nexus_volume  * volume,
                      char                 * dirpath,
                      char                 * plain_name,
                      char                ** nexus_name,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_lookup(sgx_backend->enclave_id, &ret, dirpath, plain_name, &uuid);

    if (err) {
        log_error("ecall_fs_lookup() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    if (ret == 0) {
        *nexus_name = nexus_uuid_to_alt64(&uuid);
    }

    return 0;
}

int
sgx_backend_fs_filldir(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * nexus_name,
                       char                ** plain_name,
                       void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    ret = nexus_uuid_from_alt64(&uuid, nexus_name);
    if (ret != 0) {
        log_error("could not derive uuid from '%s'\n", nexus_name);
        return -1;
    }

    err = ecall_fs_filldir(sgx_backend->enclave_id, &ret, dirpath, &uuid, plain_name);

    if (err || ret) {
        log_error("ecall_fs_filldir() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    return 0;
}
