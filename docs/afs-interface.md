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

Other notable facts about AFS:
* AFS possess a global lock that ensures the mutual exclusion when
  communicating with the server.
* When fetching files from the server, AFS fetches the chunk "on-demand".

## Kernel Level Shim
We integrate the nexus daemon using a kernel-level shim layer. The shim is
split into main parts: a patch and a device driver.  Our patch intercepts the
RPC calls at the `VNOPS` layer, and then calls the corresponding handlers in
the device driver. Once the userspace daemon completes processing, the response
is then used to modify the parameters of the RPC call.

The device driver implements a communication channel to transmit data using
`fread/fwrite` system calls. As it is structured, 


## ShimLayer API

### Creating files && directories.
```c
/**
 * @param parent_dentry is the dentry to the parent directory
 * @param plain_name is the name of new file/directory
 * @param type if it is a file or directory
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_shim_create(
    struct dentry * parent_dentry,
    char * plain_name,
    enum entry_type type,
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
nexus_shim_remove(
    struct dentry * parent_dentry,
    char * plain_name,
    enum entry_type type,
    char ** dest_obfuscated_name
)
```

### Lookup files and directories
This is by far the most common operation in AFS; converts a file name to an
inode.  In AFS, the CacheManager issues an RPC request to the fileserver.
However, since the file name is obfuscated on the server, we need to convert
the plain file name into its obfuscated equivalent.
```c
/**
 * @param parent_dentry is the dentry to the parent directory
 * @param plain_name is the name of new file/directory/symlink
 * @param type if it is a file/directory/symlink
 * @param dest_obfuscated_name is the corresponding name from the daemon
 */
int
nexus_shim_lookup(
    struct dentry * parent_dentry,
    char * plain_name,
    enum entry_type type,
    char ** dest_obfuscated_name
)
```

### Filldir (called by `ls`)
Lists the files and subdirectories in a given directory. For NEXUS, this is the
reverse of the lookup: converts the obfuscated name to the plain name.
```c
/**
 * @param parent_dentry is the dentry to the parent directory
 * @param obfuscated_name is the name of new file/directory/symlink
 * @param type if it is a file/directory/symlink
 * @param dest_plain_name is the corresponding name from the daemon
 */
int
nexus_shim_filldir(
    struct dentry * parent_dentry,
    char * obfuscated_name,
    enum entry_type type,
    char ** dest_plain_name
)
```

### Rename/Move files
```c
/**
 * @param from_dentry the source directory
 * @param oldname the old name
 * @param to_dentry 
 * @param newname
 * @param old_obfuscated_name
 * @param new_obfuscated_name
 */
int
nexus_shim_rename(
    struct dentry * from_dentry,
    char * oldname,
    struct dentry * to_dentry,
    char * newname,
    char ** old_obfuscated_name,
    char ** new_obfuscated_name
)
```
