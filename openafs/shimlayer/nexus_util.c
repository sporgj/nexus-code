
#include <linux/slab.h>
#include <linux/mm.h>
#include "nexus_util.h"




void *
nexus_kmalloc(size_t size,
	      gfp_t  flags)
{
    void * addr = kmalloc(size, flags);

    nexus_ptrs_alloced++;
    
    return addr;
}


int
nexus_get_cpu()
{
    u32 cpu_id = get_cpu(); 
    put_cpu();
    return cpu_id;
}
