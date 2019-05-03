#pragma once


/// copied from: https://github.com/rsbx/container_of/blob/container_of/offsetof.h

#ifndef offsetof
#define offsetof(CONTAINER_TYPE, MEMBER_NAME)                                                      \
    ((size_t)((char *)&(((CONTAINER_TYPE *)(0))->MEMBER_NAME) - (char *)(0)))
#endif /* offsetof */

#ifndef container_of
#define container_of(MEMBER_POINTER, CONTAINER_TYPE, MEMBER_NAME)                                  \
    ((CONTAINER_TYPE *)((char *)(MEMBER_POINTER)-offsetof(CONTAINER_TYPE, MEMBER_NAME)))
#endif
