#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <nexus_util.h>
#include <nexus_log.h>


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


static char *
my_strnjoin(char * dest, const char * join, const char * src, size_t max)
{
    size_t len1  = strnlen(dest, max);
    size_t len2  = (join == NULL) ? 0 : strnlen(join, max);
    size_t len3  = strnlen(src, max);
    size_t total = len1 + len2 + len3;
    if (total > max) {
	// XXX should we report here??
        return NULL;
    }

    char * result = realloc(dest, total + 1);
    if (result == NULL) {
        log_error("allocation error");
        return NULL;
    }

    if (join != NULL) {
        memcpy(result + len1, join, len2);
    }

    memcpy(result + len1 + len2, src, len3);
    result[total] = '\0';
    return result;
}

char *
nexus_strncat(char * dest, const char * src, size_t max)
{
    return my_strnjoin(dest, NULL, src, max);
}



char *
nexus_filepath_from_name(char * directory, const char * filename)
{
    return my_strnjoin(directory, "/", filename, PATH_MAX);
}

char *
nexus_filepath_from_uuid(const char * dirpath, struct nexus_uuid * uuid)
{
    char * fullpath = NULL;
    char * fname    = NULL;

    fname = nexus_uuid_to_string(uuid);

    fullpath = strndup(dirpath, PATH_MAX);
    fullpath = nexus_filepath_from_name(fullpath, fname);

    free(fname);

    return fullpath;
}
