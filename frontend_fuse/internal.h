#pragma once

#include <nexus_log.h>
#include <nexus_util.h>

extern char * volume_path;

int
start_fuse(struct fuse_args * args);
