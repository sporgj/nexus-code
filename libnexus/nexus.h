#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "nexus_types.h"


int nexus_init();


// volume management
int
nexus_create_volume(const char * metadata_dirpath,
                    const char * publickey_fpath,
                    const char * volumekey_fpath);

int
nexus_mount_volume(char * volume_path,
		   char * vol_key_path,
                   char * pub_key_path,
                   char * prv_key_path);









// directory operations

int
nexus_new(char                 * parent_dir,
	  char                 * fname,
	  nexus_fs_obj_type_t    type,
	  char                ** shadow_name_dest);

int
nexus_hardlink(char  * new_path,
	       char  * old_path,
	       char ** dest_obfuscated_name);

int
nexus_symlink(char  * target_path,
	      char  * link_path,
	      char ** shadow_name_dest);

/**
 * Returns the raw file name of an encoded path
 * @param dir_path is the directory in which the file resides
 * @param encoded_name is the encoded file name
 * @param raw_name_dest is the resulting the raw file name,
 * set to NULL if error (ex. file not be found)
 * @return 0 on success
 */
/* JRL: What is a raw filename ? */
int
nexus_filldir(char                 * dir_path,
	      char                 * nexus_name,
	      nexus_fs_obj_type_t    type,
	      char                ** file_name);



int
nexus_lookup (char                 * dir_path,
	      char                 * file_name,
	      nexus_fs_obj_type_t    type,
	      char                ** nexus_name);

int
nexus_remove (char                 * dir_path,
	      char                 * file_name,
	      nexus_fs_obj_type_t    type,
	      char                ** nexus_name);

int
nexus_move(char  * old_dir,
	   char  * old_name,
	   char  * new_dir,
	   char  * new_name,
	   char ** old_nexus_name,
	   char ** new_nexus_name);

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
nexus_setacl(char * path,
	      char * acl);
#ifdef __cplusplus
}
#endif
