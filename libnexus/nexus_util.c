/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <execinfo.h>

#include <nexus_util.h>
#include <nexus_log.h>


/* Not thread safe... */
#define BACKTRACE_SIZE 128
static void * backtrace_buffer[BACKTRACE_SIZE];


void
nexus_print_backtrace()
{
    int     sym_cnt  = 0;
    char ** sym_strs = NULL;

    int i = 0;
    
    sym_cnt  = backtrace(backtrace_buffer, BACKTRACE_SIZE);
    sym_strs = backtrace_symbols(backtrace_buffer, sym_cnt);

    log_error("Nexus Backtrace: (sym_cnt = %d)\n", sym_cnt);
    
    if (sym_strs == NULL) {
	/* Failed to translate symbols, print out the raw addresses */

	log_error("Error: Could not translate symbols\n");
	
	for (i = 0; i < sym_cnt; i++) {
	    log_error("\t(%p)\n", backtrace_buffer[i]); 
	}

    } else {

	for (i = 0; i < sym_cnt; i++) {
	    log_error("\t%s\n",sym_strs[i]); 
	}

	nexus_free(sym_strs);
    }
    
    return;
}

void *
nexus_malloc(size_t size)
{
    void * ptr = NULL;

    ptr = calloc(size, 1);

    if (ptr == NULL) {
	/* This should never happen, but if it does 
	 * it means we are almost certainly going down hard. 
	 * Try to print out what we can, but note that the 
	 * failures are most likely cascading here. There 
	 * is a good chance nothing will show up, and we 
	 * might still crash on a segfault.
	 */
	log_error("Malloc Failure for size %lu\n", size);
	nexus_print_backtrace();
	exit(-1);
    }
    
    return ptr;
}

// https://gist.github.com/ccbrown/9722406
void
nexus_hexdump(void * ptr, size_t size)
{
    uint8_t * data = (uint8_t *)ptr;
    char ascii[17];
    size_t i, j;

    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' '
            && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

int
nexus_strtou8(char    * str,
	      uint8_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if (tmp > UCHAR_MAX) {
	/* value exceeded requested size */
	return -1;
    }
	   
    *value = (uint8_t)tmp;    
    return 0;
}

int
nexus_strtoi8(char    * str,
	      int8_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if ((tmp > SCHAR_MAX) ||
	(tmp < SCHAR_MIN)) {
	/* value exceeded requested size */
	return -1;
    }
	   	
    *value = (int8_t)tmp;    
    return 0;
}



int
nexus_strtou16(char     * str,
	       uint16_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if (tmp > USHRT_MAX) {
	/* value exceeded requested size */
	return -1;
    }
	   
    *value = (uint16_t)tmp;    
    return 0;
}

int
nexus_strtoi16(char     * str,
	       int16_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }

    if ((tmp > SHRT_MAX) ||
	(tmp < SHRT_MIN)) {
	/* value exceeded requested size */
	return -1;
    }
	   	
    *value = (int16_t)tmp;    
    return 0;
}

int
nexus_strtou32(char     * str,
	       uint32_t * value)
{
    unsigned long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoul(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   
    *value = (uint32_t)tmp;    
    return 0;
}

int
nexus_strtoi32(char     * str,
	       int32_t * value)
{
    long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtol(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   	
    *value = (int32_t)tmp;    
    return 0;
}


int
nexus_strtou64(char     * str,
	       uint64_t * value)
{
    unsigned long long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoull(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   
    *value = (uint64_t)tmp;    
    return 0;
}
int
nexus_strtoi64(char    * str,
	       int64_t * value)
{
    long long tmp = 0;

    char * end  = NULL;
    int    base = 0;
    
    
    if ((str == NULL) || (*str == '\0')) {
	/*  String was either NULL or empty */
	log_error("Invalid string\n");
	return -1;
    }
    
    if (strlen(str) > 2) {
	if ((*(str + 1) == 'x') ||
	    (*(str + 1) == 'X')) {
	    base = 16;
	}
    }

    tmp = strtoll(str, &end, base);

    if (end == str) {
	/* String contained non-numerics */
	return -1;
    }
	   	
    *value = (int64_t)tmp;    
    return 0;
}


