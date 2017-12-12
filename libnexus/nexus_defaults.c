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
#include <nexus_defaults.h>

#define DEFAULT_VOLUME_PATH       "$HOME/nexus-volume"

#define DEFAULT_VOL_KEY_FILENAME  "$HOME/.nexus/volume_key"
#define DEFAULT_PUB_KEY_FILENAME  "$HOME/.nexus/public_key"
#define DEFAULT_PRV_KEY_FILENAME  "$HOME/.nexus/private_key"

struct nexus_defaults nexus_defaults;


int 
nexus_defaults_init()
{
    wordexp_t volume_path_exp;
    wordexp_t vol_key_filename_exp;
    wordexp_t pub_key_filename_exp;
    wordexp_t prv_key_filename_exp;

    wordexp(DEFAULT_VOLUME_PATH,      &volume_path_exp,      0);
    wordexp(DEFAULT_VOL_KEY_FILENAME, &vol_key_filename_exp, 0);
    wordexp(DEFAULT_PUB_KEY_FILENAME, &pub_key_filename_exp, 0);
    wordexp(DEFAULT_PRV_KEY_FILENAME, &prv_key_filename_exp, 0);

    
    nexus_defaults.volume_path         = strndup(volume_path_exp.we_wordv[0],      PATH_MAX);
    nexus_defaults.volume_key_path     = strndup(vol_key_filename_exp.we_wordv[0], PATH_MAX);
    nexus_defaults.user_pub_key_path   = strndup(pub_key_filename_exp.we_wordv[0], PATH_MAX);
    nexus_defaults.user_prv_key_path   = strndup(prv_key_filename_exp.we_wordv[0], PATH_MAX);

    
    wordfree(&volume_path_exp);
    wordfree(&vol_key_filename_exp);
    wordfree(&pub_key_filename_exp);
    wordfree(&prv_key_filename_exp);

    return 0;
}




