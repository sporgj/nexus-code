#pragma once


#define nexus_free(ptr) {       \
        free(ptr);              \
        ptr = NULL;             \
}
