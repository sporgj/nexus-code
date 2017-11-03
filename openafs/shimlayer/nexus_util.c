
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mm.h>

#include "nexus_util.h"



u64 nexus_ptrs_freed   = 0;
u64 nexus_ptrs_alloced = 0;


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





s8
nexus_atoi8(s8 dflt, char * str) 
{
    s8 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtos8(str, 0, &tmp) != 0) {
	return dflt;
    }
    
    return tmp;
}

u8
nexus_atou8(u8 dflt, char * str) 
{
    u8 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtou8(str, 0, &tmp) != 0) {
	return dflt;
    }
    
    return tmp;
}

s16
nexus_atoi16(s16 dflt, char * str) 
{
    s16 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtos16(str, 0, &tmp) != 0) {
	return dflt;
    }

    return tmp;
}

u16
nexus_atou16(u16 dflt, char * str) 
{
    u16 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtou16(str, 0, &tmp) != 0) {
	return dflt;
    }
    
    return tmp;
}

s32
nexus_atoi32(s32 dflt, char * str) 
{
    s32 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtos32(str, 0, &tmp) != 0) {
	return dflt;
    }
    
    return tmp;
}




u32
nexus_atou32(u32 dflt, char * str) 
{
    u32 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtou32(str, 0, &tmp) != 0) {
	return dflt;
    }

    return tmp;
}

s64
nexus_atoi64(s64 dflt, char * str) 
{
    s64 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtos64(str, 0, &tmp) != 0) {
	return dflt;
    }

    return tmp;
}


u64
nexus_atou64(u64 dflt, char * str) 
{
    u64 tmp = 0;
    
    if ((str == NULL) || (*str == '\0')) {
        /*  String was either NULL or empty */
        return dflt;
    }

    if (kstrtou64(str, 0, &tmp) != 0) {
	return dflt;
    }

    return tmp;
}
