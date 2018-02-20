#pragma once

#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_json.h>
#include <nexus_datastore.h>
#include <nexus_volume.h>

extern char * datastore_path;

extern struct nexus_volume * mounted_volume;


int
start_fuse(struct fuse_args * args);

// handler.c

int
handle_create(const char * fullpath, nexus_dirent_type_t type);
