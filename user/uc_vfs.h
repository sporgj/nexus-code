#pragma once

/**
 * Allocates a new dirnode and stores it to disk
 * @param parent_dir
 * @param fname
 * @param shadow_name_dest
 */
int
vfs_alloc_dirnode(const char * parent_dir,
                  const char * fname,
                  char ** shadow_name_dest);
