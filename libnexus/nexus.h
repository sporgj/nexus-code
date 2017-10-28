#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


typedef enum {
    
    NEXUS_ANY  = 0,
    NEXUS_FILE = 1,
    NEXUS_DIR  = 2,
    NEXUS_LINK = 3
    
} nexus_fs_obj_type_t;



/* JRL: What do these even mean in the context of Nexus???? */
struct nexus_fs_acl {
    uint64_t    read   : 1;
    uint64_t    write  : 1;
    uint64_t    insert : 1;
    uint64_t    lookup : 1;
    uint64_t    delete : 1;
    uint64_t    lock   : 1;
    uint64_t    admin  : 1;
};

int
dirops_new(const char           * parent_dir,
           const char           * fname,
           nexus_fs_obj_type_t    type,
           char                ** shadow_name_dest);

/**
 * Creates a hardlink between two paths.
 * @param new_path
 * @param old_path
 * @param dest_obfuscated_name
 * @return 0 on success
 */
int
dirops_hardlink(const char  * new_path,
                const char  * old_path,
                char       ** dest_obfuscated_name);

int
dirops_symlink(const char  * target_path,
               const char  * link_path,
               char       ** shadow_name_dest);

/**
 * Returns the raw file name of an encoded path
 * @param dir_path is the directory in which the file resides
 * @param encoded_name is the encoded file name
 * @param raw_name_dest is the resulting the raw file name,
 * set to NULL if error (ex. file not be found)
 * @return 0 on success
 */
int
dirops_filldir(const char * dir_path,
              const char * encoded_name,
              nexus_fs_obj_type_t type,
              char ** raw_name_dest);

int
dirops_lookup(const char * parent_dir,
              const char * fname,
              nexus_fs_obj_type_t type,
              char ** dest_obfuscated_name);

int
dirops_remove(const char * parent_dir,
              const char * fname,
              nexus_fs_obj_type_t type,
              char ** dest_obfuscated_name);

int
dirops_move(const char * from_dir,
            const char * oldname,
            const char * to_dir,
            const char * newname,
            char ** dest_old_obfuscated_name,
            char ** dest_new_obfuscated_name);

int
dirops_setacl(const char * path, const char * acl);

int
dirops_checkacl(const char * path, struct nexus_fs_acl rights, int is_dir);
#ifdef __cplusplus
}
#endif
