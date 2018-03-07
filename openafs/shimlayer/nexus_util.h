#ifndef __NEXUS_UTIL_H__
#define __NEXUS_UTIL_H__


#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/slab.h>


extern u64 nexus_ptrs_freed;
extern u64 nexus_ptrs_alloced;


int nexus_get_cpu(void);


void * nexus_kmalloc(size_t size, gfp_t  flags);

#define nexus_kfree(ptr)			\
    do {					\
	kfree(ptr);				\
	ptr = NULL;				\
						\
	nexus_ptrs_freed++;			\
    } while (0)



s8  nexus_atoi8 (s8  dflt, char * str);
u8  nexus_atou8 (u8  dflt, char * str);
s16 nexus_atoi16(s16 dflt, char * str);
u16 nexus_atou16(u16 dflt, char * str);
s32 nexus_atoi32(s32 dflt, char * str);
u32 nexus_atou32(u32 dflt, char * str);
s64 nexus_atoi64(s64 dflt, char * str);
u64 nexus_atou64(u64 dflt, char * str);



#define nexus_printk(fmt, args...)                                     \
    do {                                                                \
        task_lock(current);                                             \
        printk("NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)

#define NEXUS_ERROR(fmt, args...)                                             \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_ERR "NEXUS> [%s] (%u) %s(%d): " fmt, current->comm, nexus_get_cpu(),  __FILE__, __LINE__, ##args); \
        task_unlock(current);                                           \
    } while (0)

#define NEXUS_WARNING(fmt, args...)                                           \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_WARNING "NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)

#ifdef NXDEBUG
#define NEXUS_DEBUG(fmt, args...)                                             \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_DEBUG "NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)
#else
#define NEXUS_DEBUG(fmt, args...)
#endif




#endif
