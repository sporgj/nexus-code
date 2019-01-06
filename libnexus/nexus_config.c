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
#include <unistd.h>
#include <assert.h>


#include <wordexp.h>


#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_config.h>


#define DEFAULT_USER_DATA_DIR        "$HOME/.nexus"
#define DEFAULT_KEY_FILENAME         DEFAULT_USER_DATA_DIR "/user.key"
#define DEFAULT_INSTANCE_FILENAME    DEFAULT_USER_DATA_DIR "/instance.json"

#define MAX_USERNAME_LEN 32

extern uint8_t nexus_default_vol_cfg_start[];
extern uint8_t nexus_default_vol_cfg_end[];


struct nexus_config nexus_config;
char * nexus_default_volume_config = NULL;


int
nexus_config_init()
{
    {
        wordexp_t user_data_dir_exp;
        wordexp_t key_filename_exp;
        wordexp_t instance_filename_exp;

        wordexp(DEFAULT_USER_DATA_DIR, &user_data_dir_exp, 0);
        wordexp(DEFAULT_KEY_FILENAME, &key_filename_exp, 0);
        wordexp(DEFAULT_INSTANCE_FILENAME, &instance_filename_exp, 0);

        nexus_config.user_data_dir = strndup(user_data_dir_exp.we_wordv[0], PATH_MAX);
        nexus_config.user_key_path = strndup(key_filename_exp.we_wordv[0], PATH_MAX);
        nexus_config.instance_path = strndup(instance_filename_exp.we_wordv[0], PATH_MAX);

        wordfree(&user_data_dir_exp);
        wordfree(&key_filename_exp);
        wordfree(&instance_filename_exp);
    }

    {
        char * tmp_username = getenv("USER");

        if (tmp_username == NULL) {
            /* Lets try something else */
            tmp_username = getlogin();
        }

        if (tmp_username == NULL) {
            /* Not sure what to do here, so lets just blow it up */
            log_error("Could not find username...\n");
            exit(-1);
        }

        nexus_config.username = strndup(tmp_username, MAX_USERNAME_LEN);
    }

    {
        char * enclave_path = getenv("NEXUS_ENCLAVE_PATH");

        nexus_config.enclave_path = NULL;

        if (enclave_path) {
            nexus_config.enclave_path = strndup(enclave_path, PATH_MAX);
        }
    }

    {
        uint32_t vol_cfg_len = nexus_default_vol_cfg_end - nexus_default_vol_cfg_start;

        nexus_default_volume_config = calloc(1, vol_cfg_len + 1);

        strncpy(nexus_default_volume_config, (char *)nexus_default_vol_cfg_start, vol_cfg_len);
    }

    return 0;
}


void
nexus_config_set_enclave_path(char * enclave_path)
{
    if (nexus_config.enclave_path) {
        nexus_free(nexus_config.enclave_path);
    }

    if (enclave_path) {
        nexus_config.enclave_path = strndup(enclave_path, PATH_MAX);
    }
}


