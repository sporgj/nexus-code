/**
 * Defines the main data structures of our small VFS
 *
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */
#pragma once

#define FUSE_USE_VERSION 31

#include <fuse3/fuse_lowlevel.h>

#include <list.h> // from nexus


struct my_dentry {
    char                  name[NEXUS_NAME_MAX];

    size_t                name_len;

    struct nexus_uuid     uuid;

    fuse_ino_t            ino; // pointer to unique inode number

    struct my_dentry    * parent;

    struct list_head      children;

    struct list_head      siblings;
};



int
vfs_init();

void
vfs_deinit();


struct my_dentry *
vfs_get_dentry(fuse_ino_t ino);

struct my_dentry *
vfs_add_dentry(struct my_dentry * parent, char * name, fuse_ino_t ino);



struct my_dentry *
dentry_create(struct my_dentry * parent, char * name, fuse_ino_t ino);

void
dentry_delete_and_free(struct my_dentry * dentry);

struct my_dentry *
dentry_alloc();

struct my_dentry *
dentry_lookup(struct my_dentry * parent, const char * name);

char *
dentry_get_fullpath(struct my_dentry * dentry);
