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

#define AFSX_CRYPTO_BLK_SIZE 16
#define TOBLKSIZE(x) x + 16 - (x % 16)

#define UC_ENCRYPT    0x00000001
#define UC_DECRYPT    0x00000002
#define UC_VERIFY     0x00000004

#define UC_HARDLINK     0
#define UC_SOFTLINK     1

typedef uint32_t uc_crypto_op_t;

typedef enum {
    UC_FILE = 0x00000001,
    UC_DIR = 0x00000002,
    UC_LINK = 0x00000004,
    UC_ANY = UC_FILE | UC_DIR | UC_LINK,
} ucafs_entry_type;

