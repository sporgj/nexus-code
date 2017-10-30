#pragma once
#include <linux/types.h>

// the number of pages to allocate for the transfer buffer
#define NEXUS_DATA_BUFPAGES 1
#define NEXUS_DATA_BUFLEN (PAGE_SIZE << NEXUS_DATA_BUFPAGES)
