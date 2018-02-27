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
start_fuse(int argc, char * argv[], char * datastore_path);

// handler.c

int
handle_create(const char * path, nexus_dirent_type_t type, char ** nexus_fullpath);

int
handle_delete(const char * path, char ** nexus_fullpath);

int
handle_lookup(const char * path, char ** nexus_fullpath);

int
handle_filldir(const char * path, const char * name, char ** nexus_name);
