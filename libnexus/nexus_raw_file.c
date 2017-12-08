
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>



#include <nexus_raw_file.h>
#include <nexus_util.h>
#include <nexus_log.h>


int
nexus_read_raw_file(char     * path,
		    uint8_t ** buf,
		    size_t   * size)
{
    FILE        * file_ptr = NULL;
    struct stat   file_stats;
    
    size_t        file_size  = 0;
    uint8_t     * file_data = NULL;
    
    int ret = 0;
    
    ret = stat(path, &file_stats);

    if (ret == -1) {
	log_error("Could not stat file (%s)\n", path);
	return -1;
    }

    file_size = file_stats.st_size;

    /* This check is probably not necessary.... */
    if (file_size <= 0) {
	log_error("Invalid file size for (%s)\n", path);
	return -1;
    }

    file_data = calloc(1, file_size);

    if (file_data == NULL) {
        log_error("could not allocate buffer for file (%s) (size=%zu)\n", path, file_size);
	return -1;
    }

    
    file_ptr = fopen(path, "rb");

    if (file_ptr == NULL) {
        log_error("Could not open file (%s)\n", path);
	goto out;
    }

    ret = fread(file_data, file_size, 1, file_ptr);

    ret--; /* This is a funky op to make the ret value be correct 
	    * fread will return 1 on success, and 0 on error (see fread man page)
	    */

    if (ret == -1) {
	nexus_free(file_data);
	goto out;
    }

    *buf  = file_data;
    *size = file_size;
    
 out:
    fclose(file_ptr);
    
    return ret;
}



int
nexus_write_raw_file(char   * path,
		     void   * buf,
		     size_t   size)
{
    FILE * file_ptr = NULL;

    int ret = 0;

    file_ptr = fopen(path, "wb");

    if (file_ptr == NULL) {
        log_error("Failed top open file (%s)\n", path);
        return -1;
    }

    ret = fwrite(buf, size, 1, file_ptr);

    ret--; /* This is a funky op to make the ret value be correct 
	    * fread will return 1 on success, and 0 on error (see fwrite man page)
	    */

    if (ret == -1) {
	log_error("Failed to write file (%s) (size=%zu)", path, size);
    }

    fclose(file_ptr);

    return ret;
}
