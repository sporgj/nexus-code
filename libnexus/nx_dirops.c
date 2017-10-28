#include <string.h>

#include "nexus.h"

// TODO
int
dirops_new(const char * parent_dir,
           const char * fname,
           nexus_fs_obj_type_t type,
           char ** shadow_name_dest)
{
    return 0;
}

// TODO
int
dirops_lookup(const char * parent_dir,
              const char * fname,
              nexus_fs_obj_type_t type,
              char ** dest_obfuscated_name)
{
    return 0;
}

// TODO
int
dirops_filldir(const char * parent_dir,
               const char * fname,
               nexus_fs_obj_type_t type,
               char ** dest_obfuscated_name)
{
    return 0;
}

// TODO
int
dirops_hardlink(const char * new_path,
                const char * old_path,
                char ** dest_obfuscated_name)
{
    return 0;
}

// TODO
int
dirops_symlink(const char * target_path,
               const char * link_path,
               char ** shadow_name_dest)
{
    return 0;
}

// TODO
int
dirops_remove(const char * parent_dir,
              const char * fname,
              nexus_fs_obj_type_t type,
              char ** dest_obfuscated_name)
{
    return 0;
}

// TODO
int
dirops_move(const char * from_dir,
            const char * oldname,
            const char * to_dir,
            const char * newname,
            char ** dest_old_obfuscated_name,
            char ** dest_new_obfuscated_name)
{
    return 0;
}

// TODO
int
dirops_setacl(const char * path, const char * acl)
{
    return 0;
}

// TODO
int
dirops_checkacl(const char * path, struct nexus_fs_acl rights, int is_dir)
{
    return 0;
}
