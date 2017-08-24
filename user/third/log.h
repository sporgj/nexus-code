#ifndef __LOG_h__
#define __LOG_h__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef LOGLEVEL
#define LOGLEVEL 5
#endif

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#if LOGLEVEL < 3
#define NDEBUG 1
#endif

#ifdef NDEBUG
/* compile with all debug messages removed */
#define log_debug(M, ...)
#else
#ifdef LOG_NOCOLORS
  #define log_debug(M, ...) fprintf(stderr, "DEBUG " M " at %s (%s:%d) \n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
#else
  #define log_debug(M, ...) fprintf(stderr, "\33[34mDEBUG\33[39m " M "  \33[90m at %s (%s:%d) \33[39m\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
#endif /* NOCOLORS */
#endif /* NDEBUG */

/* safe readable version of errno */
#define clean_errno() ""
//(errno == 0 ? "None" : strerror(errno))

#ifdef LOG_NOCOLORS
  #define log_error(M, ...) fprintf(stderr,  "ERR   " M " at %s (%s:%d)\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
  #define log_warn(M, ...) fprintf(stderr, "WARN  " M " at %s (%s:%d)\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
  #define log_info(M, ...) fprintf(stderr, "INFO  " M " at %s (%s:%d)\n", ##__VA_ARGS__, __func__, __FILENAME__, __LINE__)
#else
  #define log_error(M, ...) fprintf(stderr,  "\33[31mERR\33[39m   " M "  \33[90m at %s (%s:%d)\33[39m\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
  #define log_warn(M, ...) fprintf(stderr, "\33[91mWARN\33[39m  " M "  \33[90m at %s (%s:%d)\33[39m\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__)
  #define log_info(M, ...) fprintf(stderr, "\33[32mINFO\33[39m  " M "  \33[90m at %s (%s:%d) \33[39m\n", ##__VA_ARGS__, __func__, __FILENAME__, __LINE__)
#endif /* NOCOLORS */

#if LOGLEVEL < 4
#undef log_info
#define log_info(M, ...)
#endif

#if LOGLEVEL < 2
#undef log_warn
#define log_warn(M, ...)
#endif

#if LOGLEVEL < 1
#undef log_error
#define log_error(M, ...)
#endif

// @author judicael. TODO will change the colors for fatal
#define log_fatal log_error

#endif

