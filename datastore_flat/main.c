/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <nexus_datastore.h>
#include <nexus_json.h>


static void *
flat_init(nexus_json_obj_t cfg)
{
    return NULL;
}


static int
flat_deinit(void * priv_data)
{
    return -1;
}

static int
flat_get_uuid(struct nexus_uuid  * uuid,
	      char               * path,
	      uint8_t           ** buf,
	      uint32_t           * size,
	      void               * priv_data)
{
    return -1;
}

static int
flat_put_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      uint8_t           * buf,
	      uint32_t            size,
	      void              * priv_data)
{
    return -1;
}

static int
flat_del_uuid(struct nexus_uuid * uuid,
	      char              * path,
	      void              * priv_data)
{
    return -1;
}





static struct nexus_datastore_impl flat_datastore = {
    .name     = "FLAT",
    .init     = flat_init,
    .deinit   = flat_deinit,
    .get_uuid = flat_get_uuid,
    .put_uuid = flat_put_uuid,
    .del_uuid = flat_del_uuid
};


nexus_register_datastore(flat_datastore);
