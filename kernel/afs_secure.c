#ifdef AFS_SECURE
#include <linux/in.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/string.h>

#include "afs_secure.h"
#include "afsx.h"

static char * ignore_dirs[] = {
    "/xyz.vm/user/mirko/.afsx"
};

static struct rx_connection *conn = NULL, *ping_conn = NULL;

static int AFSX_IS_CONNECTED = 0;

int LINUX_AFSX_connect() {
    u_long host;
    struct rx_securityClass* null_securityObject;

    rx_Init(0);

    /* set the address to the current machine */
    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                            null_securityObject, AFSX_NULL);
    ping_conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                                 null_securityObject, AFSX_NULL);

    rx_SetConnDeadTime(conn, 5);
    rx_SetConnDeadTime(ping_conn, 2);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    LINUX_AFSX_ping();
    return 0;
}

int LINUX_AFSX_ping(void) {
    int ret, dummy;

    /* lower the timeout, 2 */
    ret = AFSX_fversion(ping_conn, 0, &dummy);

    dummy = AFSX_IS_CONNECTED;
    AFSX_IS_CONNECTED = (ret == 0);
    if (dummy != AFSX_IS_CONNECTED) {
        printk(KERN_ERR "connected: %d, ret = %d\n", AFSX_IS_CONNECTED, ret);
    }
    return 0;
}

/**
 * return 0 
 */
int LINUX_AFSX_ignore_path_bool(char * dir) {
    int i;
    int len;
    char * ignore;

    for (i = 0; i < sizeof(ignore_dirs)/sizeof(char *); i++) {
        ignore = ignore_dirs[i];
        len = strlen(ignore);
        if (strnstr(dir, ignore, len + 1)) {
            return 1;
        }
    }
    return 0;
}

int LINUX_AFSX_newfile(char** dest, char* fpath) {
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    ret = AFSX_fnew(conn, fpath, dest);
    if (ret) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "error on file %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_realname(char ** dest, char * fname, char * dirpath) {
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_frealname(conn, fname, dirpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "realname error: %s\n", dirpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_lookup(char ** dest, char * fpath) {
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_fencodename(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "lookup error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

int LINUX_AFSX_delfile(char ** dest, char * fpath) {
    int ret;

    *dest = NULL;
    if (!AFSX_IS_CONNECTED) {
        return -1;
    }

    if ((ret = AFSX_fremove(conn, fpath, dest))) {
        if (ret == AFSX_STATUS_ERROR) {
            printk(KERN_ERR "delete error: %s\n", fpath);
        }
        *dest = NULL;
    }

    return ret;
}

#endif
