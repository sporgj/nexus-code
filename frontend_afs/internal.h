#pragma once

#include "afs.h"
#include "handler.h"

#include <nexus_util.h>
#include <nexus_log.h>
#include <nexus_volume.h>
#include <nexus_datastore.h>

extern struct nexus_volume * mounted_volume;

extern char * datastore_path;

extern size_t datastore_pathlen;
