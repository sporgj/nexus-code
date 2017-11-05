
#pragma once

#include <linux/wait.h>
#include <linux/kernel.h>
#include <linux/kref.h>



#define MAX_CMD_RESP_SIZE 1024

struct nexus_volume {
    char * path;

    struct kref refcount; 

    struct {
	wait_queue_head_t   daemon_waitq;
	struct mutex        lock;
	
	uint32_t            cmd_len;
	uint8_t           * cmd_data;
	
	uint8_t             active;
	uint8_t             complete;
	uint8_t             error;
	
	uint32_t            resp_len;
	uint8_t           * resp_data;
    } cmd_queue;

    struct list_head node;
};



int create_nexus_volume(char * path);


struct nexus_volume * nexus_get_volume(char * path);

void nexus_put_volume(struct nexus_volume * vol);


int nexus_send_cmd(struct nexus_volume * vol,
		   uint32_t              cmd_len,
		   uint8_t             * cmd_data,
		   uint32_t            * resp_len,
		   uint8_t            ** resp_data);
