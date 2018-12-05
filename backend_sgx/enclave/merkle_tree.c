/*
 * Responsible for maintaining merkle hash tree
 */

struct nexus_mac * root_mac;


/* 
 * Initializes the merkle hash tree, by loading
 * the hash file
 */
int
merkle_init(nexus_uuid *vol_ptr) {

    if (vol_ptr != NULL) {
        int size = 0;
        void *d_ptr;
        
        //making an ocall to get the hash of the root node
        if (ocall_merkle_get(vol_ptr, d_ptr, &size)) {
            log_error("ocall_stash_get FAILED\n");
            return -1;
        }
        
        if(d_ptr == NULL) {
            log_error("ocall_merkle_get FAILED d_ptr issue");
            return -1;
        }
        
        root_mac = nexus_malloc(sizeof (struct nexus_mac));
        
        if (root_mac == NULL) {
            log_error("root_mac malloc FAILED\n");
            return -1;
        }
                
        memcpy(root_mac, d_ptr, size);
    } else {
        //need volume info
        return -1;
    }
    return 0;
}

/* 
 * Updates mac value of the modified node in the
 * parent.
 */
int
merkle_update(struct nexus_uuid node_uuid) {
    while(!isNodeRoot(node_uuid)) {
        struct nexus_uuid parent_uuid = getParent(node_uuid);
        
        //TODO: How to get the mac? Depends on the hooks
        update_dir_rec(parent_uuid, node_uuid);
        node_uuid = parent_uuid;
    }
}
