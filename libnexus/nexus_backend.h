#pragma once

#include "nexus.h"

extern int
nexus_init_backend();

extern int
nexus_exit_backend();

// authenticates with the backend
extern int
nexus_auth_backend(struct supernode * supernode,
                   struct volumekey * volumekey,
                   const char *       publickey_fpath,
                   const char *       privatekey_fpath);

// volume management
extern int
backend_volume_create(struct uuid *      supernode_uuid,
                      struct uuid *      root_uuid,
                      const char *       publickey_fpath,
                      struct supernode * supernode_out,
                      struct dirnode *   dirnode_out,
                      struct volumekey * volume_out);

// dirnode management
extern int
backend_dirnode_new(struct uuid *     dirnode_uuid,
                    struct uuid *     root_uuid,
                    struct dirnode ** p_dirnode);

extern int
backend_dirnode_add(struct dirnode *    parent_dirnode,
                    struct uuid *       uuid,
                    const char *        fname,
                    nexus_fs_obj_type_t type);

extern int
backend_dirnode_find_by_uuid(struct dirnode *      dirnode,
                             struct uuid *         uuid,
                             char **               p_fname,
                             nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_find_by_name(struct dirnode *      dirnode,
                             char *                fname,
                             struct uuid *         uuid,
                             nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_remove(struct dirnode *      dirnode,
                       char *                fname,
                       struct uuid *         uuid,
                       nexus_fs_obj_type_t * p_type);

extern int
backend_dirnode_serialize(struct dirnode *  dirnode,
                          struct dirnode ** p_sealed_dirnode);
