#include "ucafs_kern.h"
#include <linux/dcache.h>

static const char * afs_prefix = "/afs";
static const uint32_t afs_prefix_len = 4;

static char * watch_dirs[] = { UC_AFS_PATH_KERN"/"UC_AFS_WATCH };
static const int watch_dir_len[] = { sizeof(watch_dirs[0]) - 1 };

struct rx_connection *conn = NULL, *ping_conn = NULL;

int UCAFS_IS_CONNECTED = 0;

int
ucafs_connect(void)
{
    u_long host;
    struct rx_securityClass * null_securityObject;

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

    printk(KERN_ERR "watch: %s\n", watch_dirs[0]);

    if (conn == NULL || ping_conn == NULL) {
        /* maybe have a retry */
        printk(KERN_ERR "Connection to AFSX server failed\n");
        return -1;
    }
    return 0;
}

int
ucafs_ping(void)
{
    int ret, dummy;

    /* lower the timeout, 2 */
    ret = AFSX_fversion(ping_conn, 0, &dummy);

    dummy = UCAFS_IS_CONNECTED;
    UCAFS_IS_CONNECTED = (ret == 0);
    if (dummy != UCAFS_IS_CONNECTED) {
        printk(KERN_ERR "connected: %d, ret = %d\n", UCAFS_IS_CONNECTED, ret);
    }
    return 0;
}

char *
uc_mkpath(const char * parent_path, const char * fname)
{
    int len1 = strlen(parent_path), len2 = strlen(fname);
    char * rv = (char *)kmalloc(len1 + len2 + 2, GFP_KERNEL);
    memcpy(rv, parent_path, len1);
    rv[len1] = '/';
    memcpy(rv + len1 + 1, fname, len2);
    rv[len1 + len2 + 1] = '\0';

    return rv;
}

struct rx_connection *
__get_conn(void)
{
    u_long host;
    struct rx_securityClass * null_securityObject;

    host = htonl(INADDR_LOOPBACK);
    null_securityObject = rxnull_NewClientSecurityObject();
    conn = rx_NewConnection(host, AFSX_SERVER_PORT, AFSX_SERVICE_ID,
                            null_securityObject, AFSX_NULL);

    rx_GetConnection(conn);
    return conn;
}

void
__put_conn(struct rx_connection * c)
{
    rx_PutConnection(c);
}

inline ucafs_entry_type
uc_vnode_type(struct vcache * vnode)
{
    if (vnode == NULL) {
        return UC_ANY;
    }

    switch(vType(vnode)) {
        case VREG: return UC_FILE;
        case VDIR: return UC_DIR;
        case VLNK: return UC_LINK;
    }

    return UC_ANY;
}

inline ucafs_entry_type
dentry_type(struct dentry * dentry)
{
    if (d_is_file(dentry)) {
        return UC_FILE;
    } else if (d_is_dir(dentry)) {
        return UC_DIR;
    } else if (d_is_symlink(dentry)) {
        return UC_LINK;
    }

    return UC_ANY;
}

inline ucafs_entry_type
vnode_type(struct vcache * avc)
{
    return dentry_type(d_find_alias(AFSTOV(avc)));
}

bool
startsWith(const char * pre, const char * str)
{
    size_t lenpre = strlen(pre), lenstr = strlen(str);
    return lenstr < lenpre ? 0 : strncmp(pre, str, lenpre) == 0;
}

/**
 * whether to ignore a vnode or not.
 * if not ignore, dest will be set to the full path of the directory
 *
 * @return bool true if path is to be ignored
 */
int
__is_dentry_ignored(struct dentry * dentry, char ** dest)
{
    int len, i, total_len;
    char *path, *curr_dir, *result;
    char buf[512];

    if (dentry == NULL) {
        return 1;
    }

    /* TODO cache the inode number
    printk(KERN_ERR "\npar=%p, dentry=%p, iname=%s d_name.len=%d
    dentry_name=%s",
           dentry->d_parent, dentry, dentry->d_iname, dentry->d_name.len,
           dentry->d_name.name); */
    path = dentry_path_raw(dentry, buf, sizeof(buf));

    if (IS_ERR_OR_NULL(path)) {
        print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf,
                       sizeof(buf), 1);
        return 1;
    }

    /*
    printk(KERN_ERR "path=%p\n", path);
    print_hex_dump(KERN_ERR, "", DUMP_PREFIX_ADDRESS, 32, 1, buf, sizeof(buf),
                   1); */

    for (i = 0; i < sizeof(watch_dirs) / sizeof(char *); i++) {
        curr_dir = watch_dirs[i];

        if (startsWith(curr_dir, path)) {
            // TODO maybe check the prefix on the name
            // we're good
            if (dest) {
                len = strlen(path);
                total_len = afs_prefix_len + len;
                result = kmalloc(total_len + 1, GFP_KERNEL);
                memcpy(result, afs_prefix, afs_prefix_len);
                memcpy(result + afs_prefix_len, path, len);
                result[total_len] = '\0';
                *dest = result;
            }
            return 0;
        }
    }
    return 1;
}

inline int
UCAFS_ignore_dentry(struct dentry * dp, char ** dest)
{
    return __is_dentry_ignored(dp, dest);
}

inline int
__is_vnode_ignored(struct vcache * avc, char ** dest)
{
    // if it's null, just ignore it
    if (avc == NULL) {
        return 1;
    }

    return __is_dentry_ignored(d_find_alias(AFSTOV(avc)), dest);
}

inline int
ucafs_vnode_path(struct vcache * avc, char ** dest)
{
    return __is_vnode_ignored(avc, dest);
}

int
_ucafs_init_fetch(struct afs_conn * tc,
                  struct rx_connection * rxconn,
                  struct vcache * avc,
                  afs_offs_t base,
                  afs_uint32 size,
                  afs_int32 * alength,
                  int * srv_64bit,
                  struct rx_call ** afs_call)
{
    int code = 0, code1 = 0;
#ifdef AFS_64BIT_CLIENT
    afs_uint32 length_hi = 0;
#endif
    afs_uint32 length = 0, bytes;
    struct rx_call * call;

    *srv_64bit = 0;

    RX_AFS_GUNLOCK();
    call = rx_NewCall(rxconn);
    RX_AFS_GLOCK();
    if (call) {
#ifdef AFS_64BIT_CLIENT
        afs_size_t length64;     /* as returned from server */
        if (!afs_serverHasNo64Bit(tc)) {
            afs_uint64 llbytes = size;
            *srv_64bit = 1;
            RX_AFS_GUNLOCK();
            code = StartRXAFS_FetchData64(call,
                    (struct AFSFid *) &avc->f.fid.Fid,
                    base, llbytes);
            if (code != 0) {
                RX_AFS_GLOCK();
                afs_Trace2(afs_iclSetp, CM_TRACE_FETCH64CODE,
                        ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code);
            } else {
                bytes = rx_Read(call, (char *)&length_hi, sizeof(afs_int32));
                RX_AFS_GLOCK();
                if (bytes == sizeof(afs_int32)) {
                    length_hi = ntohl(length_hi);
                } else {
                    code = rx_Error(call);
                    RX_AFS_GUNLOCK();
                    code1 = rx_EndCall(call, code);
                    RX_AFS_GLOCK();
                    call = NULL;
                }
            }
        }
        if (code == RXGEN_OPCODE || afs_serverHasNo64Bit(tc)) {
            if (base > 0x7FFFFFFF) {
                code = EFBIG;
            } else {
                afs_uint32 pos;
                pos = base;
                RX_AFS_GUNLOCK();
                if (!call)
                    call = rx_NewCall(rxconn);
                code =
                    StartRXAFS_FetchData(
                            call, (struct AFSFid*)&avc->f.fid.Fid,
                            pos, size);
                RX_AFS_GLOCK();
            }
            afs_serverSetNo64Bit(tc);
        }
        if (!code) {
            RX_AFS_GUNLOCK();
            bytes = rx_Read(call, (char *)&length, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (bytes == sizeof(afs_int32))
                length = ntohl(length);
            else {
                RX_AFS_GUNLOCK();
                code = rx_Error(call);
                code1 = rx_EndCall(call, code);
                call = NULL;
                length = 0;
                RX_AFS_GLOCK();
            }
        }
        FillInt64(length64, length_hi, length);

        if (!code) {
            /* Check if the fileserver said our length is bigger than can fit
             * in a signed 32-bit integer. If it is, we can't handle that, so
             * error out. */
            if (length64 > MAX_AFS_INT32) {
                static int warned;
                if (!warned) {
                    warned = 1;
                    afs_warn("afs: Warning: FetchData64 returned too much data "
                            "(length64 %u.%u); this should not happen! "
                            "Aborting fetch request.\n",
                            length_hi, length);
                }
                RX_AFS_GUNLOCK();
                code = rx_EndCall(call, RX_PROTOCOL_ERROR);
                call = NULL;
                length = 0;
                RX_AFS_GLOCK();
                code = code != 0 ? code : EIO;
            }
        }

        if (!code) {
            /* Check if the fileserver said our length was negative. If it
             * is, just treat it as a 0 length, since some older fileservers
             * returned negative numbers when they meant to return 0. Note
             * that we must do this in this 64-bit-specific block, since
             * length64 being negative will screw up our conversion to the
             * 32-bit 'alength' below. */
            if (length64 < 0) {
                length_hi = length = 0;
                FillInt64(length64, 0, 0);
            }
        }

        afs_Trace3(afs_iclSetp, CM_TRACE_FETCH64LENG,
                ICL_TYPE_POINTER, avc, ICL_TYPE_INT32, code,
                ICL_TYPE_OFFSET,
                ICL_HANDLE_OFFSET(length64));
        if (!code)
            *alength = length;
#else /* AFS_64BIT_CLIENT */
        RX_AFS_GUNLOCK();
        code = StartRXAFS_FetchData(call, (struct AFSFid *)&avc->f.fid.Fid,
                base, size);
        RX_AFS_GLOCK();
        if (code == 0) {
            RX_AFS_GUNLOCK();
            bytes =
                rx_Read(call, (char *)&length, sizeof(afs_int32));
            RX_AFS_GLOCK();
            if (bytes == sizeof(afs_int32)) {
                *alength = ntohl(length);
                if (*alength < 0) {
                    /* Older fileservers can return a negative length when they
                     * meant to return 0; just assume negative lengths were
                     * meant to be 0 lengths. */
                    *alength = 0;
                }
            } else {
                code = rx_Error(call);
                code1 = rx_EndCall(call, code);
                call = NULL;
            }
        }
#endif /* AFS_64BIT_CLIENT */
    } else
        code = -1;

    /* We need to cast here, in order to avoid issues if *alength is
     * negative. Some, older, fileservers can return a negative length,
     * which the rest of the code deals correctly with. */
    if (code == 0 && *alength > (afs_int32) size) {
        /* The fileserver told us it is going to send more data than we
         * requested. It shouldn't do that, and accepting that much data
         * can make us take up more cache space than we're supposed to,
         * so error. */
        static int warned;
        if (!warned) {
            warned = 1;
            afs_warn("afs: Warning: FetchData64 returned more data than "
                    "requested (requested %ld, got %ld); this should not "
                    "happen! Aborting fetch request.\n",
                    (long)size, (long)*alength);
        }
        code = rx_Error(call);
        RX_AFS_GUNLOCK();
        code1 = rx_EndCall(call, code);
        RX_AFS_GLOCK();
        call = NULL;
        code = EIO;
    }

    if (!code && code1)
        code = code1;

    *afs_call = call;

    return code;
}

int
_ucafs_end_fetch(struct rx_call * afs_call,
                 struct afs_FetchOutput * o,
                 int srv_64bit,
                 int error)
{
    int code;
#ifdef AFS_64BIT_CLIENT
    if (srv_64bit)
        code = EndRXAFS_FetchData64(afs_call, &o->OutStatus, &o->CallBack,
                                    &o->tsync);
    else
        code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack,
                                  &o->tsync);
#else
    code = EndRXAFS_FetchData(afs_call, &o->OutStatus, &o->CallBack, &o->tsync);
#endif
    code = rx_EndCall(afs_call, code | error);

    return code;
}
