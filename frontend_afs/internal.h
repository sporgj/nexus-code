#pragma once

#include "afs.h"
#include "handler.h"

#include <nexus_util.h>
#include <nexus_log.h>
#include <nexus_volume.h>
#include <nexus_datastore.h>


#ifdef TRACE
#define log_trace(fmt, ...) fprintf(stderr, ". " fmt, ##__VA_ARGS__)
#else
#define log_trace(fmt, ...)
#endif

extern struct nexus_volume * mounted_volume;

extern char * datastore_path;

extern size_t datastore_pathlen;

// for the data transfer
extern uint8_t * global_databuf_addr;
extern size_t    global_databuf_size;
