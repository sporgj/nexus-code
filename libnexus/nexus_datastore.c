/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>

#include <nexus_datastore.h>

#include <nexus_hashtable.h>
#include <nexus_util.h>
#include <nexus_log.h>

static struct nexus_hashtable * datastore_table = NULL;

/*
 * This is a place holder to ensure that the _nexus_datastores section gets created by gcc
 */
static struct {} null_datastore  __attribute__((__used__))         \
__attribute__((used, __section__ ("_nexus_datastores"),            \
                   aligned(sizeof(uintptr_t))));



static uint32_t
datastore_hash_fn(uintptr_t key)
{
    char * name = (char *)key;
    return nexus_hash_buffer((uint8_t *)name, strlen(name));
}


static int
datastore_eq_fn(uintptr_t key_1,
                uintptr_t key_2)
{
    char * name_1 = (char *)key_1;
    char * name_2 = (char *)key_2;

    return (strcasecmp(name_1, name_2) == 0);
}



int
nexus_datastores_init()
{
    extern struct nexus_datastore_impl  * __start__nexus_datastores[];
    extern struct nexus_datastore_impl  * __stop__nexus_datastores[];
    struct nexus_datastore_impl        ** tmp_datastore = __start__nexus_datastores;

    int i = 0;

    log_debug("Initializing Nexus Datastores\n");

    datastore_table = nexus_create_htable(0, datastore_hash_fn, datastore_eq_fn);


    if (datastore_table == NULL) {
        log_error("Could not allocate datastore table\n");
        return -1;
    }


    while (tmp_datastore != __stop__nexus_datastores) {
        log_debug("Registering Datastore (%s)\n", (*tmp_datastore)->name);

        if (nexus_htable_search(datastore_table, (uintptr_t)((*tmp_datastore)->name))) {
            log_error("Datastore (%s) is already registered\n", (*tmp_datastore)->name);
            return -1;
        }

        if (nexus_htable_insert(
                datastore_table, (uintptr_t)((*tmp_datastore)->name), (uintptr_t)(*tmp_datastore))
            == 0) {
            log_error("Could not register datastore (%s)\n", (*tmp_datastore)->name);
            return -1;
        }

        tmp_datastore = &(__start__nexus_datastores[++i]);
    }


    return 0;
}


struct nexus_datastore *
nexus_datastore_create(char             * name,
                       nexus_json_obj_t   cfg)
{
    struct nexus_datastore      * datastore = NULL;
    struct nexus_datastore_impl * impl      = NULL;

    impl = nexus_htable_search(datastore_table, (uintptr_t)name);

    if (impl == NULL) {
        log_error("Could not find datastore implementation for (%s)\n", name);
        return NULL;
    }

    datastore = nexus_malloc(sizeof(struct nexus_datastore));


    log_debug("initializing datastore (%s)\n", name);

    datastore->impl      = impl;
    datastore->priv_data = datastore->impl->create(cfg);

    if (datastore->priv_data == NULL) {
        log_error("Error initializing datastore (%s)\n", name);
        nexus_free(datastore);
        return NULL;
    }

    return datastore;
}


int
nexus_datastore_delete(char             * name,
                       nexus_json_obj_t   cfg)
{
    struct nexus_datastore_impl * impl = NULL;

    int ret = 0;

    impl = nexus_htable_search(datastore_table, (uintptr_t)name);

    if (impl == NULL) {
	log_error("Could not find datastore implementation for (%s)\n", name);
	return -1;
    }

    ret = impl->delete(cfg);

    if (ret == -1) {
	log_error("Could not delete datastore (%s)\n", name);
    }

    return ret;
}


struct nexus_datastore *
nexus_datastore_open(char             * name,
                     nexus_json_obj_t   cfg)
{
    struct nexus_datastore      * datastore = NULL;
    struct nexus_datastore_impl * impl      = NULL;

    impl = nexus_htable_search(datastore_table, (uintptr_t)name);

    if (impl == NULL) {
        log_error("Could not find datastore implementation for (%s)\n", name);
        return NULL;
    }

    datastore = calloc(sizeof(struct nexus_datastore), 1);

    if (datastore == NULL) {
        log_error("Could not allocate nexus_datastore\n");
        return NULL;
    }

    log_debug("initializing datastore (%s)\n", name);

    datastore->impl      = impl;
    datastore->priv_data = datastore->impl->open(cfg);

    if (datastore->priv_data == NULL) {
	log_error("Error initializing datastore (%s)\n", name);
	nexus_free(datastore);
	return NULL;
    }

    return datastore;
}


int
nexus_datastore_close(struct nexus_datastore * datastore)
{
    log_debug("Shutting down nexus datastore (%s)\n", datastore->impl->name);

    datastore->impl->close(datastore->priv_data);

    return 0;
}



int
nexus_datastore_get_uuid(struct nexus_datastore     * datastore,
                         struct nexus_uuid          * uuid,
                         char                       * path,
                         uint8_t                   ** buf,
                         uint32_t                   * size)
{
    return datastore->impl->get_uuid(uuid, path, buf, size, datastore->priv_data);
}


int
nexus_datastore_put_uuid(struct nexus_datastore     * datastore,
                         struct nexus_uuid          * uuid,
                         char                       * path,
                         uint8_t                    * buf,
                         uint32_t                     size)
{
    return datastore->impl->put_uuid(uuid, path, buf, size, datastore->priv_data);
}



struct nexus_file_handle *
nexus_datastore_fopen(struct nexus_datastore   * datastore,
                      struct nexus_uuid        * uuid,
                      char                     * path,
                      nexus_io_flags_t           flags)
{
    return datastore->impl->fopen(uuid, path, flags, datastore->priv_data);
}

int
nexus_datastore_fread(struct nexus_datastore    * datastore,
                      struct nexus_file_handle  * file_handle,
                      uint8_t                  ** buf,
                      size_t                    * size)
{
    return datastore->impl->fread(file_handle, buf, size, datastore->priv_data);
}

int
nexus_datastore_fwrite(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle,
                       uint8_t                  * buf,
                       size_t                     size)
{
    return datastore->impl->fwrite(file_handle, buf, size, datastore->priv_data);
}

int
nexus_datastore_fflush(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle)
{
    return datastore->impl->fflush(file_handle, datastore->priv_data);
}

int
nexus_datastore_fclose(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle)
{
    return datastore->impl->fclose(file_handle, datastore->priv_data);
}


int
nexus_datastore_update_uuid(struct nexus_datastore  * datastore,
                            struct nexus_uuid       * uuid,
                            char                    * path,
                            uint8_t                 * buf,
                            uint32_t                  size)
{
    return datastore->impl->update_uuid(uuid, path, buf, size, datastore->priv_data);
}

int
nexus_datastore_stat_uuid(struct nexus_datastore      * datastore,
                          struct nexus_uuid           * uuid,
                          char                        * path,
                          struct stat                 * stat_buf)
{
    return datastore->impl->stat_uuid(uuid, path, stat_buf, datastore->priv_data);
}

int
nexus_datastore_getattr(struct nexus_datastore * datastore,
                        struct nexus_uuid      * uuid,
                        struct nexus_fs_attr   * attrs)
{
    if (datastore->impl->getattr == NULL) {
        log_error("getattr NOT Implemented for %s datastore\n", datastore->impl->name);
        return -1;
    }

    return datastore->impl->getattr(uuid, attrs, datastore->priv_data);
}

int
nexus_datastore_set_mode(struct nexus_datastore * datastore, struct nexus_uuid * uuid, mode_t mode)
{
    if (datastore->impl->set_mode == NULL) {
        log_error("set_mode NOT Implemented for %s datastore\n", datastore->impl->name);
        return -1;
    }

    return datastore->impl->set_mode(uuid, mode, datastore->priv_data);
}

int
nexus_datastore_truncate(struct nexus_datastore * datastore, struct nexus_uuid * uuid, size_t size)
{
    if (datastore->impl->truncate == NULL) {
        log_error("truncate NOT Implemented for %s datastore\n", datastore->impl->name);
        return -1;
    }

    return datastore->impl->truncate(uuid, size, datastore->priv_data);
}

int
nexus_datastore_set_times(struct nexus_datastore  * datastore,
                          struct nexus_uuid       * uuid,
                          size_t                    access_time,
                          size_t                    mod_time)
{
    if (datastore->impl->set_times == NULL) {
        log_error("set_times NOT Implemented for %s datastore\n", datastore->impl->name);
        return -1;
    }

    return datastore->impl->set_times(uuid, access_time, mod_time, datastore->priv_data);

}

int
nexus_datastore_new_uuid(struct nexus_datastore * datastore, struct nexus_uuid * uuid, char * path)
{
    return datastore->impl->new_uuid(uuid, path, datastore->priv_data);
}

int
nexus_datastore_touch_uuid(struct nexus_datastore * datastore,
                           struct nexus_uuid      * uuid,
                           mode_t                   mode,
                           char                   * path)
{
    return datastore->impl->touch_uuid(uuid, mode, path, datastore->priv_data);
}

int
nexus_datastore_del_uuid(struct nexus_datastore * datastore, struct nexus_uuid * uuid, char * path)
{
    return datastore->impl->del_uuid(uuid, path, datastore->priv_data);
}

int
nexus_datastore_hardlink_uuid(struct nexus_datastore * datastore,
                              struct nexus_uuid      * link_uuid,
                              char                   * link_path,
                              struct nexus_uuid      * target_uuid,
                              char                   * target_path)
{
    if (datastore->impl->hardlink_uuid == NULL) {
	log_error("hardlink_uuid not implemented for datastore: %s\n", datastore->impl->name);
	return -1;
    }

    return datastore->impl->hardlink_uuid(link_uuid,
                                          link_path,
                                          target_uuid,
                                          target_path,
                                          datastore->priv_data);
}

int
nexus_datastore_rename_uuid(struct nexus_datastore   * datastore,
                            struct nexus_uuid        * from_uuid,
                            char                     * from_path,
                            struct nexus_uuid        * to_uuid,
                            char                     * to_path)
{
    return datastore->impl->rename_uuid(from_uuid,
                                        from_path,
                                        to_uuid,
                                        to_path,
                                        datastore->priv_data);
}


int
nexus_datastore_copy_uuid(struct nexus_datastore * src_datastore,
                          struct nexus_datastore * dst_datastore,
                          struct nexus_uuid      * uuid,
                          bool                     force_copy)
{
    return dst_datastore->impl->copy_uuid(src_datastore, uuid, force_copy, dst_datastore->priv_data);
}
