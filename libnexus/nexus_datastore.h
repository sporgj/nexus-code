#pragma once


#include <nexus_uuid.h>

int nexus_datastores_init();
int nexus_datastores_exit();




struct nexus_datastore_impl {
    char * name;

    int (*init)();

    int (*get_uuid)(struct nexus_uuid  * uuid,
		    char               * path,
		    uint8_t           ** buf,
		    uint32_t           * size);

    int (*put_uuid)(struct nexus_uuid * uuid,
		    char              * path,
		    uint8_t           * buf,
		    uint32_t            size);


    int (*del_uuid)(struct nexus_uuid * uuid,
		    char              * path);
    
};



struct nexus_datastore {
    struct nexus_datastore_impl * impl;
};


#define nexus_register_datastore(datastore)				\
    static struct nexus_datastore_impl * _nexus_datastore		\
    __attribute__((used))						\
         __attribute__((unused, __section__("_nexus_datastores"),	\
                        aligned(sizeof(void *))))			\
         = &datastore;


