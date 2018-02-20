#pragma once

#include <nexus_log.h>
#include <nexus_util.h>
#include <nexus_json.h>
#include <nexus_datastore.h>
#include <nexus_volume.h>

extern char * datastore_path;

int
start_fuse(struct fuse_args * args);
