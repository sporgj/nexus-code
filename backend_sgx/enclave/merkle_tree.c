/*
 * Responsible for maintaining merkle hash tree
 */

#include "metadata.h"
#include "dentry.h"


struct nexus_mac * root_mac;


/* 
 * Initializes the merkle hash tree, by loading
 * the hash file
 */
int
merkle_init(nexus_uuid *vol_ptr) {

    if (vol_ptr != NULL) {
        
        //root_mac = nexus_malloc(sizeof (struct nexus_mac));
        
        //making an ocall to load vol merkle file
        int err = -1;
        int ret = -1;

        err = ocall_merkle_init(&ret, vol_ptr, root_mac);

        if (err || ret) {
            log_error("merkle_init FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }   
        
        if(d_ptr == NULL) {
            log_error("ocall_merkle_get FAILED d_ptr issue");
            return -1;
        }
        
        if (root_mac == NULL) {
            log_error("root_mac malloc FAILED\n");
            return -1;
        }
                
    } else {
        //need volume info
        log_error("merkle_init FAILED\n");
        return -1;
    }
    return 0;
}

/* 
 * Updates mac value of the modified node in the
 * parent.
 */
int
merkle_update(struct nexus_dentry *parent_dentry, struct nexus_uuid *child_uuid, struct nexus_mac *child_mac) {
    
    if(parent_dentry != NULL) {
    
        struct nexus_dirnode *parent = parent_dentry->metadata->dirnode;
    
        struct list_head * curr = NULL;

        list_for_each(curr, &parent->dirents_list) {
            struct dir_entry * dir_entry = __dir_entry_from_dirents_list(curr);
            if(dir_entry->dir_rec->link_uuid == child_uuid) {
                dir_entry->dir_rec->link_mac = child_mac;
                break;
            }
        }
    
        return nexus_metadata_store(parent);
    } else {
        //we have reached the root
                
        int err = -1;
        int ret = -1;

        err = ocall_merkle_get(&ret, child_mac);

        if (err || ret) {
            log_error("merkle_update FAILED (err=%d, ret=%d)\n", err, ret);
            return -1;
        }   
    }
    return 0;
}
