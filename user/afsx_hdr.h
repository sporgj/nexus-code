#pragma once

#define AFSX_SERVER_PORT       9462
#define AFSX_SERVICE_PORT      0
#define AFSX_SERVICE_ID        4

#define AFSX_STATUS_SUCCESS        0
#define AFSX_STATUS_ERROR          1
#define AFSX_STATUS_NOOP           2

#define AFSX_PACKET_SIZE   4096

#define AFSX_FNAME_MAX         256
#define AFSX_PATH_MAX       1024

#define UCAFS_FNAME_PREFIX "afsx_"
#define UCAFS_FNAME_PREFIX_LEN sizeof(UCAFS_FNAME_PREFIX) - 1

#define UCAFS_MAX_CELLS 5

#define UCAFS_WRITEOP 1
#define UCAFS_READOP 0

#define TOBLKSIZE(x) 16 - (x % 16)
