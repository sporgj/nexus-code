#ifndef __LOG_h__
#define __LOG_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

// TODO add flag to makefile
#define DEBUG

#define log_error(fmt, ...) fprintf(stderr, "error> %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#ifdef DEBUG
#define log_debug(fmt, ...) fprintf(stderr, "debug> " fmt "\n", ##__VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif




#endif

