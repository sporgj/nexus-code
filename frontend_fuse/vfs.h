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

    size_t                lookup_count;

    size_t                openers;

    nexus_dirent_type_t   type;

    struct my_dentry    * parent;

    struct list_head      children;

    struct list_head      siblings;
};


struct my_file {
    struct my_dentry    * dentry;
};


struct my_dir {
    size_t                file_count;

    size_t                readdir_offset; // the current offset of READDIR operation

    struct my_dentry    * dentry;
};


int
vfs_init();

void
vfs_deinit();


struct my_dentry *
vfs_get_dentry(fuse_ino_t ino);

struct my_dentry *
vfs_add_dentry(struct my_dentry * parent, char * name, struct nexus_uuid * uuid, nexus_dirent_type_t type);

void
vfs_remove_inode(fuse_ino_t ino);



struct my_file *
vfs_create_file(struct my_dentry * dentry);

void
vfs_delete_file(struct my_file * file_ptr);


struct my_dir *
vfs_create_dir(struct my_dentry * dentry);

void
vfs_delete_dir(struct my_dir * dir_ptr);



// dentry.c

struct my_dentry *
dentry_create(struct my_dentry * parent, char * name, struct nexus_uuid * uuid, nexus_dirent_type_t type);

void
dentry_delete_and_free(struct my_dentry * dentry);

struct my_dentry *
dentry_alloc();

struct my_dentry *
dentry_lookup(struct my_dentry * parent, const char * name);

char *
dentry_get_fullpath(struct my_dentry * dentry);

char *
dentry_get_parent_fullpath(struct my_dentry * dentry);
