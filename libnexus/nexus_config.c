/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <wordexp.h>


#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_config.h>


#define DEFAULT_USER_DATA_DIR   "$HOME/.nexus"
#define DEFAULT_KEY_FILENAME    DEFAULT_USER_DATA_DIR "/user.key"

extern uint8_t nexus_default_vol_cfg_start[];
extern uint8_t nexus_default_vol_cfg_end[];


struct nexus_config nexus_config;
char * nexus_default_volume_config = NULL;


int 
nexus_config_init()
{
    wordexp_t user_data_dir_exp;
    wordexp_t key_filename_exp;

    wordexp(DEFAULT_USER_DATA_DIR, &user_data_dir_exp, 0);
    wordexp(DEFAULT_KEY_FILENAME,  &key_filename_exp,  0);

    nexus_config.user_data_dir   = strndup(user_data_dir_exp.we_wordv[0], PATH_MAX);
    nexus_config.user_key_path   = strndup(key_filename_exp.we_wordv[0],  PATH_MAX);

    
    wordfree(&user_data_dir_exp);
    wordfree(&key_filename_exp);

    {
	uint32_t vol_cfg_len = nexus_default_vol_cfg_end - nexus_default_vol_cfg_end;

	nexus_default_volume_config = calloc(1, vol_cfg_len + 1);
	
	strncpy(nexus_config.volume_config, (char *)nexus_default_vol_cfg_start, vol_cfg_len);
    }
    
    return 0;
}




