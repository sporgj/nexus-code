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

    return ret;
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

    if (err) {
        log_error("ecall_fs_filldir() FAILED. (err=0x%x)\n", err);
        return -1;
    }

    return ret;
}

int
sgx_backend_fs_symlink(struct nexus_volume  * volume,
                       char                 * dirpath,
                       char                 * link_name,
                       char                 * target_path,
                       char                ** nexus_name,
                       void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_symlink(sgx_backend->enclave_id, &ret, dirpath, link_name, target_path, &uuid);

    if (err || ret) {
        log_error("ecall_fs_symlink() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *nexus_name = nexus_uuid_to_alt64(&uuid);

    return 0;
}

int
sgx_backend_fs_hardlink(struct nexus_volume  * volume,
                        char                 * link_dirpath,
                        char                 * link_name,
                        char                 * target_dirpath,
                        char                 * target_name,
                        char                ** nexus_name,
                        void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid uuid;

    int err = -1;
    int ret = -1;


    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_hardlink(sgx_backend->enclave_id,
                            &ret,
                            link_dirpath,
                            link_name,
                            target_dirpath,
                            target_name,
                            &uuid);

    if (err || ret) {
        log_error("ecall_fs_hardlink() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *nexus_name = nexus_uuid_to_alt64(&uuid);

    return 0;
}

int
sgx_backend_fs_rename(struct nexus_volume  * volume,
                      char                 * from_dirpath,
                      char                 * oldname,
                      char                 * to_dirpath,
                      char                 * newname,
                      char                ** old_nexusname,
                      char                ** new_nexusname,
                      void                 * priv_data)
{
    struct sgx_backend * sgx_backend = NULL;

    struct nexus_uuid old_uuid;
    struct nexus_uuid new_uuid;

    int err = -1;
    int ret = -1;

    sgx_backend = (struct sgx_backend *)priv_data;

    err = ecall_fs_rename(sgx_backend->enclave_id,
                          &ret,
                          from_dirpath,
                          oldname,
                          to_dirpath,
                          newname,
                          &old_uuid,
                          &new_uuid);

    if (err || ret) {
        log_error("ecall_fs_rename() FAILED. (err=0x%x, ret=%d)\n", err, ret);
        return -1;
    }

    *old_nexusname = nexus_uuid_to_alt64(&old_uuid);
    *new_nexusname = nexus_uuid_to_alt64(&new_uuid);

    return 0;
}
