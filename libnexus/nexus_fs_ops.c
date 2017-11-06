#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/limits.h>

#include "nexus.h"

// TODO
int
nexus_new(char * parent_dir,
	  char * fname,
	  nexus_fs_obj_type_t type,
	  char ** dest_obfuscated_name)
{
    return -1;
}

// TODO
int
nexus_lookup(char                 * dir_path,
	     char                 * file_name,
	     nexus_fs_obj_type_t    type,
	     char                ** nexus_name)
{
    *nexus_name = file_name;

    printf("Nexus Lookup for %s/%s\n", dir_path, file_name);
    
    return 0;
}

// TODO
int
nexus_filldir(char                 * dir_path,
	      char                 * file_name,
	      nexus_fs_obj_type_t    type,
	      char                ** nexus_name)
{
    return -1;
}

// TODO
int
nexus_hardlink(char  * new_path,
	       char  * old_path,
	       char ** nexus_name)
{
    return -1;
}

// TODO
int
nexus_symlink(char  * target_path,
	      char  * link_path,
	      char ** nexus_name)
{
    return -1;
}

// TODO
int
nexus_remove(char                 * dir_path,
	     char                 * file_name,
	     nexus_fs_obj_type_t    type,
	     char                ** nexus_name)
{
    *nexus_name = strndup(file_name, NAME_MAX);
    return -1;
}

// TODO
int
nexus_move(char  * old_dir,
	   char  * old_name,
	   char  * new_dir,
	   char  * new_name,
	   char ** old_nexus_name,
	   char ** new_nexus_name)
{
    return -1;
}

// TODO
int
nexus_setacl(char * path, char * acl)
{
    return -1;
}
