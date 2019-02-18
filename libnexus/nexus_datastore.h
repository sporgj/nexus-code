/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdint.h>

#include <sys/stat.h>

#include <nexus_fs.h>
#include <nexus_uuid.h>
#include <nexus_json.h>



struct nexus_datastore {
    struct nexus_datastore_impl * impl;

    void * priv_data;
};


// create/delete

struct nexus_datastore *
nexus_datastore_create(char * name, nexus_json_obj_t datastore_cfg);

int
nexus_datastore_delete(char * name, nexus_json_obj_t datastore_cfg);




// open/close

struct nexus_datastore *
nexus_datastore_open(char * name, nexus_json_obj_t datastore_cfg);

int
nexus_datastore_close(struct nexus_datastore * datastore);



// metadata file operations

int
nexus_datastore_get_uuid(struct nexus_datastore    * datastore,
                         struct nexus_uuid         * uuid,
                         char                      * path,
                         uint8_t                  ** buf,
                         uint32_t                  * size);

int
nexus_datastore_put_uuid(struct nexus_datastore    * datastore,
                         struct nexus_uuid         * uuid,
                         char                      * path,
                         uint8_t                   * buf,
                         uint32_t                    size);

int
nexus_datastore_update_uuid(struct nexus_datastore * datastore,
                            struct nexus_uuid      * uuid,
                            char                   * path,
                            uint8_t                * buf,
                            uint32_t                 size);




struct nexus_file_handle *
nexus_datastore_fopen(struct nexus_datastore    * datastore,
                      struct nexus_uuid         * uuid,
                      char                      * path,
                      nexus_io_flags_t            flags);

int
nexus_datastore_fread(struct nexus_datastore    * datastore,
                      struct nexus_file_handle  * file_handle,
                      uint8_t                  ** buf,
                      size_t                    * size);

int
nexus_datastore_fwrite(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle,
                       uint8_t                  * buf,
                       size_t                     size);

int
nexus_datastore_fclose(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle);

int
nexus_datastore_fflush(struct nexus_datastore   * datastore,
                       struct nexus_file_handle * file_handle);



// metadata directory operations

int
nexus_datastore_stat_uuid(struct nexus_datastore      * datastore,
                          struct nexus_uuid           * uuid,
                          char                        * path,
                          struct stat                 * stat_buf);

int
nexus_datastore_getattr(struct nexus_datastore * datastore,
                        struct nexus_uuid      * uuid,
                        struct nexus_fs_attr   * attrs);

int
nexus_datastore_set_mode(struct nexus_datastore * datastore, struct nexus_uuid * uuid, mode_t mode);

int
nexus_datastore_truncate(struct nexus_datastore * datastore, struct nexus_uuid * uuid, size_t size);

int
nexus_datastore_set_times(struct nexus_datastore  * datastore,
                          struct nexus_uuid       * uuid,
                          size_t                    access_time,
                          size_t                    mod_time);

int
nexus_datastore_new_uuid(struct nexus_datastore      * datastore,
                         struct nexus_uuid           * uuid,
                         char                        * path);

int
nexus_datastore_touch_uuid(struct nexus_datastore    * datastore,
                           struct nexus_uuid         * uuid,
                           mode_t                      mode,
                           char                      * path);

int
nexus_datastore_del_uuid(struct nexus_datastore      * datastore,
                         struct nexus_uuid           * uuid,
                         char                        * path);

int
nexus_datastore_hardlink_uuid(struct nexus_datastore * datastore,
                              struct nexus_uuid      * link_uuid,
                              char                   * link_path,
                              struct nexus_uuid      * target_uuid,
                              char                   * target_path);

int
nexus_datastore_rename_uuid(struct nexus_datastore   * datastore,
                            struct nexus_uuid        * from_uuid,
                            char                     * from_path,
                            struct nexus_uuid        * to_uuid,
                            char                     * to_path);



int nexus_datastores_init();
int nexus_datastores_exit();




struct nexus_datastore_impl {
    char * name;

    void * (*create)(nexus_json_obj_t datastore_cfg);
    int    (*delete)(nexus_json_obj_t datastore_cfg);

    void * (*open)(nexus_json_obj_t datastore_cfg);
    int    (*close)(void * priv_data);


    /**
     * Runs a 'stat' call on the uuid file
     * @param uuid
     * @param path
     * @param stat
     * @param priv_data
     */
    int (*stat_uuid)(struct nexus_uuid  * uuid,
                     char               * path,
                     struct stat        * stat_buf,
                     void               * priv_data);

    /**
     * getattr returns the posix stat values
     */
    int (*getattr)(struct nexus_uuid    * uuid,
                   struct nexus_fs_attr * attrs,
                   void                 * priv_data);


    int (*set_mode)(struct nexus_uuid * uuid, mode_t mode, void * priv_data);

    int (*truncate)(struct nexus_uuid * uuid, size_t size, void * priv_data);

    int (*set_times)(struct nexus_uuid * uuid,
                     size_t              access_time,
                     size_t              mod_time,
                     void              * priv_data);

    /**
     * Gets uuid content
     * @param uuid
     * @param path
     * @param p_buf
     * @param p_size
     * @param priv_data
     */
    int (*get_uuid)(struct nexus_uuid  * uuid,
                    char               * path,
                    uint8_t           ** p_buf,
                    uint32_t           * p_size,
                    void               * priv_data);

    /**
     * Creates/updates uuid with buffer and content
     * @param uuid
     * @param path
     * @param buf
     * @param size
     * @param priv_data
     */
    int (*put_uuid)(struct nexus_uuid * uuid,
                    char              * path,
                    uint8_t           * buf,
                    uint32_t            size,
                    void              * priv_data);

    /**
     * Updates an existing metadata object
     * @param uuid
     * @param path
     * @param buf
     * @param size
     * @param priv_data
     */
    int (*update_uuid)(struct nexus_uuid * uuid,
                       char              * path,
                       uint8_t           * buf,
                       uint32_t            size,
                       void              * priv_data);


    /**
     * Acquires an exclusive lock on metadata and returns a nexus_file_handle
     */
    struct nexus_file_handle * (*fopen)(struct nexus_uuid  * uuid,
                                        char               * path,
                                        nexus_io_flags_t     flags,
                                        void               * priv_data);

    /**
     * Reads the contents of the metadata file
     */
    int (*fread)(struct nexus_file_handle  * file_handle,
                      uint8_t                  ** buf,
                      size_t                    * size,
                      void                      * priv_data);

    /**
     * Writes to a locked file
     * @param buf
     * @param size
     * @param priv_data
     */
    int (*fwrite)(struct nexus_file_handle * file_handle,
                       uint8_t                  * buf,
                       size_t                     size,
                       void                     * priv_data);

    /**
     * Flushes the file
     */
    int (*fflush)(struct nexus_file_handle * file_handle, void * priv_data);

    /**
     * Closes the file
     */
    int (*fclose)(struct nexus_file_handle * file_handle, void * priv_data);



    /**
     * Creates an empty file in the datastore
     * @param uuid
     * @param path
     * @param priv_data
     */
    int (*new_uuid)(struct nexus_uuid * uuid, char * path, void * priv_data);

    int (*touch_uuid)(struct nexus_uuid * uuid, mode_t mode, char * path, void * priv_data);

    /**
     * Removes uuid from the metadata store
     * @param uuid
     * @param path
     * @param priv_data
     */
    int (*del_uuid)(struct nexus_uuid * uuid, char * path, void * priv_data);

    /**
     * Hardlinks two uuids
     * @param link_uuid
     * @param link_path
     * @param target_uuid
     * @param target_path
     * @param priv_data
     */
    int (*hardlink_uuid)(struct nexus_uuid * link_uuid,
                         char              * link_path,
                         struct nexus_uuid * target_uuid,
                         char              * target_path,
                         void              * priv_data);

    /**
     * Moves a UUID from one portion to another
     * @param from_uuid
     * @param from_path
     * @param to_uuid
     * @param to_path
     * @param priv_data
     */
    int (*rename_uuid)(struct nexus_uuid * from_uuid,
                       char              * from_path,
                       struct nexus_uuid * to_uuid,
                       char              * to_path,
                       void              * priv_data);
};




#define nexus_register_datastore(datastore)                                                        \
    static struct nexus_datastore_impl * _nexus_datastore __attribute__((used))                    \
        __attribute__((unused, __section__("_nexus_datastores"), aligned(sizeof(void *))))         \
        = &datastore;

