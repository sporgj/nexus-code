#pragma once


#include <nexus_uuid.h>
#include <nexus_json.h>


struct nexus_datastore_impl;

// JBD: referenced in datastore_flat/main.c
typedef enum {
    DATASTORE_DEFAULT_MODE = 0x0001
} nexus_datastore_mode_t;

struct nexus_datastore {
    struct nexus_datastore_impl * impl;

    void * priv_data;
};



struct nexus_datastore * nexus_datastore_create(char             * name,
					        nexus_json_obj_t   datastore_cfg);


struct nexus_datastore * nexus_datastore_open(char             * name,
					      nexus_json_obj_t   datastore_cfg);

int nexus_datastore_close(struct nexus_datastore * datastore);


int nexus_datastore_get_uuid(struct nexus_datastore * datastore,
			     struct nexus_uuid      * uuid,
			     char                   * path,
			     uint8_t               ** p_buf,
			     uint32_t               * p_size);


int nexus_datastore_put_uuid(struct nexus_datastore * datastore,
			     struct nexus_uuid      * uuid,
			     char                   * path,
			     uint8_t                * buf,
			     uint32_t                 size);


int nexus_datastore_del_uuid(struct nexus_datastore * datastore,
			     struct nexus_uuid      * uuid,
			     char                   * path);









int nexus_datastores_init();
int nexus_datastores_exit();




struct nexus_datastore_impl {
    char * name;

    void * (*create)(nexus_json_obj_t datastore_cfg);
    int    (*delete)(void * priv_data);

    void * (*open)(char *                 volume_path,
                   nexus_json_obj_t       datastore_cfg,
                   nexus_datastore_mode_t mode);

    int (*close)(void * priv_data);

    
    int (*get_uuid)(struct nexus_uuid  * uuid,
		    char               * path,
		    uint8_t           ** p_buf,
		    uint32_t           * p_size,
		    void               * priv_data);

    int (*set_uuid)(struct nexus_uuid * uuid,
		    char              * path,
		    uint8_t           * buf,
		    uint32_t            size,
		    void              * priv_data);

    /**
     * use to create a new entries in the datastore
     */
    int (*add_uuid)(struct nexus_uuid * uuid,
		    char              * path,
		    void              * priv_data);

    int (*del_uuid)(struct nexus_uuid * uuid,
		    char              * path,
		    void              * priv_data);

    
};


#define nexus_register_datastore(datastore)				\
    static struct nexus_datastore_impl * _nexus_datastore		\
    __attribute__((used))						\
         __attribute__((unused, __section__("_nexus_datastores"),	\
                        aligned(sizeof(void *))))			\
         = &datastore;


