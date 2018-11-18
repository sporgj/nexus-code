/**
 * Defines the main data structures of our small VFS
 *
 * @author Judicael Djoko <jbriand@cs.pitt.edu>
 */
#pragma once

#define FUSE_USE_VERSION 31

#include <fuse3/fuse_lowlevel.h>

#include <list.h> // from nexus


#define NEXUS_CHUNK_LOG2    (20)
#define NEXUS_CHUNK_SIZE    (1 << NEXUS_CHUNK_LOG2)


struct my_dentry;



struct file_chunk {
    bool             is_dirty;
    bool             is_valid;

    uint8_t *        buffer;
    size_t           size;
    size_t           base;
    size_t           index;
    struct list_head node;
};


struct my_inode {
    struct nexus_uuid      uuid;

    fuse_ino_t             ino;

    size_t                 lookup_count;

    struct nexus_fs_attr   attrs;


    time_t                 last_accessed;

    struct my_dentry     * dentry;
};

struct my_dentry {
    char                  name[NEXUS_NAME_MAX];

    size_t                name_len;

    nexus_dirent_type_t   type;

    struct nexus_fs_lookup lookup_info;

    size_t                refcount;


    struct my_inode     * inode;

    struct my_dentry    * parent;

    struct list_head      children;

    struct list_head      siblings;
};


struct my_file {
    int                   flags;

    size_t                offset;

    size_t                filesize;

    char                * filepath;

    struct my_dentry    * dentry;

    struct my_inode     * inode;

    bool                  is_dirty;


    size_t                chunk_count;

    struct list_head      file_chunks;

    struct list_head      open_files;
};


struct my_dir {
    size_t                file_count;

    char                * dirpath;

    size_t                readdir_offset; // the current offset of READDIR operation

    struct my_dentry    * dentry;

    struct list_head      open_dirs;
};


int
vfs_init();

void
vfs_deinit();


struct my_dentry *
vfs_get_dentry(fuse_ino_t ino);

struct my_dentry *
vfs_cache_dentry(struct my_dentry  * parent,
                 char              * name,
                 struct nexus_uuid * uuid,
                 nexus_dirent_type_t type);

struct my_dentry *
_vfs_cache_dentry(struct my_dentry * parent, char * name, struct nexus_fs_lookup * lookup_info);

void
vfs_forget_dentry(struct my_dentry * dentry);


struct my_inode *
vfs_get_inode(fuse_ino_t ino);



struct my_file *
vfs_file_alloc(struct my_dentry * dentry);

void
vfs_file_free(struct my_file * file_ptr);


struct my_dir *
vfs_dir_alloc(struct my_dentry * dentry);

void
vfs_dir_free(struct my_dir * dir_ptr);


void
inode_incr_lookup(struct my_inode * inode, uint64_t count);

void
inode_decr_lookup(struct my_inode * inode, uint64_t count);


void
file_set_clean(struct my_file * file_ptr);

void
file_set_dirty(struct my_file * file_ptr);

int
file_read(struct my_file * file_ptr,
          size_t           offset,
          size_t           size,
          uint8_t        * output_buffer,
          size_t         * output_buflen);


int
file_write(struct my_file * file_ptr,
           size_t           offset,
           size_t           size,
           uint8_t        * input_buffer,
           size_t         * bytes_read);


// dentry.c

struct my_dentry *
dentry_create(struct my_dentry * parent, char * name,nexus_dirent_type_t type);

void
dentry_delete_and_free(struct my_dentry * dentry);

struct my_dentry *
dentry_alloc();

struct my_dentry *
dentry_lookup(struct my_dentry * parent, const char * name);

void
dentry_instantiate(struct my_dentry * dentry, struct my_inode * inode);

char *
dentry_get_fullpath(struct my_dentry * dentry);

char *
dentry_get_parent_fullpath(struct my_dentry * dentry);


// copies the inode stat attributes into a destination buffer
void
dentry_export_attrs(struct my_dentry * dentry, struct stat * st_dest);


struct my_dentry *
dentry_get(struct my_dentry * dentry);

void
dentry_put(struct my_dentry * dentry);
