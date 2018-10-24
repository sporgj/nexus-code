/*
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <nexus_config.h>
#include <nexus_uuid.h>
#include <nexus_fs.h>
#include <nexus_backend.h>
#include <nexus_datastore.h>
#include <nexus_log.h>


int nexus_init(void);
int nexus_deinit(void);

/* Setup the nexus user data */
int nexus_setup(void);

// volume management
struct nexus_volume *
nexus_create_volume(char * volume_path, char * config_str);


#ifdef __cplusplus
}
#endif
