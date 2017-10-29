# AFS Interface

This document gives a high level description of the AFS interface.

## OpenAFS Internal Organization

Below are the notable directories in the AFS source code.
+ `src/afs` - the main AFS client code
+ `src/libafs` - destination folder of the libafs.ko openafs module
+ `src/venus` - contains the build for the fs directory

Breaking the `src/afs` directory:
```bash

afs
├── afs_dcache.c    # manages AFS cache
├── afs_fetchstore.c    # contains routine to push files to the server
├── LINUX   # Linux-related files
│   └── osi_vnodeops.c  # OpenAFS VFS interface
└── VNOPS   # Issues RPC calls for directory operations
    ├── afs_vnop_lookup.c  # for file lookups
    ├── afs_vnop_create.c  # create file/directories
    ├── ...
    └── afs_vnop_remove.c  # delete file/directories
```

* AFS possesses a global lock that ensures mutual exclusion when communicating
  with the server.
* AFS fetches chunks "on-demand".
* The `struct vcache` data structure is the AFS equivalent of an inode.
* `struct dcache` points to a file chunk.

## Kernel Level Shim
We integrate the nexus daemon using a kernel-level shim layer. The shim is
split into main parts: a patch and a device driver.  Our patch intercepts the
RPC calls at the `VNOPS` layer, and then calls the corresponding handlers in
the device driver. Once the userspace daemon completes processing, the response
is then used to modify the parameters of the RPC call.

The device driver implements a communication channel to transmit data using
`fread/fwrite` system calls. *TODO*.


## ShimLayer API

### Creating files && directories.
```c
/**
 * @param parent_directory is the dentry to the parent directory
 * @param plain_name is the name of new file/directory
 * @param type if it is a file or directory
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_create(
    struct vcache * parent_directory,
    char * plain_name,
    nexus_entry_type type,
    char ** dest_obfuscated_name
)
```

### Removing files and directories
```c
/**
 * @param parent_dentry is the dentry to the parent directory
 * @param plain_name is the name of new file/directory
 * @param type if it is a file or directory
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_remove(
    struct vcache * parent_directory,
    char * plain_name,
    nexus_entry_type type,
    char ** dest_obfuscated_name
)
```

### Lookup files and directories
This is by far the most common operation in AFS; converts a filepath to an
inode(aka `struct vcache`).   However, since the file name is obfuscated on the
server, we need to convert the plain filename into its obfuscated form.
```c
/**
 * @param parent_directory
 * @param plain_name is the name of new file/directory/symlink
 * @param type file/directory/symlink
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_kern_lookup(
    struct vcache * parent_directory,
    char * plain_name,
    enum entry_type type,
    char ** dest_obfuscated_name
)
```

### Filldir (called by `ls`)
Lists the files and subdirectories in a given directory. For NEXUS, this is the
reverse of the lookup: converts the obfuscated name to the plain name.

This will be called in a loop by OpenAFS, as it iterates the files/subdirectories 

```c
/**
 * @param directory, the directory which is being listed 
 * @param obfuscated_name is the file/directory/symlink
 * @param type if it is a file/directory/symlink
 * @param dest_plain_name is the corresponding name from the daemon
 */
int
nexus_kern_filldir(
    char * parent_directory,
    char * obfuscated_name,
    nexus_entry_type type,
    char ** dest_plain_name
)
```

### Rename/Move files
```c
/**
 * @param source_dir the source directory
 * @param oldname the old name
 * @param dest_dir
 * @param newname
 * @param old_obfuscated_name
 * @param new_obfuscated_name
 */
int
nexus_kern_rename(
    struct vcache * source_dir,
    char * oldname,
    struct vcache * dest_dir,
    char * newname,
    char ** old_obfuscated_name,
    char ** new_obfuscated_name
)
```

### Hardlink
```c
/**
 * @param source_link is the existing file
 * @param target_link will be the new hardlink
 * @param dest_obfuscated_name will be the new link's obfuscated name
 */
int
nexus_kern_hardlink(
    struct dentry * existing_link,
    struct dentry * new_link,
    char ** dest_obfuscated_name
)
```

### Symlinks
```c
/**
 * @param dentry path to the new "symlink"
 * @param symlink_target this is the path the link will point to
 * @param dest_obfuscated_name
 */
int nexus_kern_symlink(
    struct dentry * dentry,
    char * symlink_target,
    char ** dest_obfuscated_name
)
```

### Storing files to the server
Files in AFS are stored on close. The AFS CacheManager gathers the dirty chunk
entries, and saves them to the server using the chunk offsets.

We intercept the store operation, and send the chunk data to userspace for
encryption.

```c
/**
 * @param vcache the file being saved
 * @param dirty_dcaches the list of all the dirty dcache entries
 * @param total_size amount of data to transfer (could be less than the file size)
 * @param anewDV data version, must be incremented on success (AFS)
 * @param doProcessFS whether to refresh the vcache. Usually set to 1 (AFS)
 * @param nchunks the number of chunks
 * @param nomore if there are chunks left
 * @param afs_call is the pointer to the RPC context (already initialized by AFS)
 * @param filepath the path to the file
 * @param starting_offset the offset to the first chunk
 * @param store_ops functions current store operation (AFS)
 * @param store_ops_data the data related to the store operation (AFS)
 */
int
nexus_kern_store(struct vcache          * vcache,
                 struct dcache         ** dirty_dcaches,
                 afs_size_t               total_size,
                 afs_hyper_t            * anewDV,
                 int                    * doProcessFS,
                 struct AFSFetchStatus  * OutStatus,
                 afs_uint32               nchunks,
                 int                      nomore,
                 struct rx_call         * rx_call,
                 char                   * filepath,
                 int                      starting_offset,
                 struct storeOps        * store_ops,
                 void                   * store_ops_data)
```

### Fetching files from the server.
```c
/**
 * @param afs_conn the afs connection to the server
 * @param rxconn an RPC connection with the server.
 * @param fp a pointer to the raw chunk file (chunks are saved as files on disk)
 * @param starting_offset
 * @param dcache
 * @param vcache
 * @param dcache_size the size of the dcache entry
 * @param rx_call RPC context with the server
 * @param filepath
 */
int
nexus_kern_fetch(struct afs_conn      * afs_conn,
                 struct rx_connection * rxconn,
                 struct osi_file      * fp,
                 afs_size_t             starting_offset,
                 struct dcache        * dcache,
                 struct vcache        * vcache,
                 afs_int32              dcache_size,
                 struct rx_call       * rx_call,
                 char                 * filepath)
```

### Storing ACLs
```c
/**
 * @param vcache
 * @param acl_data AFS formatted acl data
 */
int
ucafs_kern_storeacl(struct vcache * avc,
                    AFSOpaque     * acl_data)
```

