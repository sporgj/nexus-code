#ifndef __NEXUS_UTIL_H__
#define __NEXUS_UTIL_H__


#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/gfp.h>


u64 nexus_ptrs_freed   = 0;
u64 nexus_ptrs_alloced = 0;


int nexus_get_cpu(void);


void * nexus_kmalloc(size_t size, gfp_t  flags);

#define nexus_kfree(ptr)			\
    do {					\
	kfree(ptr);				\
	ptr = NULL;				\
						\
	nexus_ptrs_freed++;			\
    } while (0)



#define nexus_printk(fmt, args...)                                     \
    do {                                                                \
        task_lock(current);                                             \
        printk("NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)

#define ERROR(fmt, args...)                                             \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_ERR "NEXUS> [%s] (%u) %s(%d): " fmt, current->comm, nexus_get_cpu(),  __FILE__, __LINE__, ##args); \
        task_unlock(current);                                           \
    } while (0)

#define WARNING(fmt, args...)                                           \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_WARNING "NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)

#define DEBUG(fmt, args...)                                             \
    do {                                                                \
        task_lock(current);                                             \
        printk(KERN_DEBUG "NEXUS> [%s] (%u): " fmt, current->comm, nexus_get_cpu(), ##args); \
        task_unlock(current);                                           \
    } while (0)





#endif
