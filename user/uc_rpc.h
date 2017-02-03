#include <stdint.h>

#include "ucafs_header.h"

#include "third/xdr.h"
#include "third/xdr_prototypes.h"

int
uc_rpc_ping(XDR * xdrs, XDR * rsp);

int
uc_rpc_dirops(uc_msg_type_t msg_type, XDR * xdrs, XDR * rsp);

int
uc_rpc_symlink(XDR * xdrs, XDR * rsp);

int
uc_rpc_hardlink(XDR * xdrs, XDR * rsp);

int
uc_rpc_rename(XDR * xdrs, XDR * rsp);

int
uc_rpc_storeacl(XDR * xdrs, XDR * xdr_out);

int
uc_rpc_xfer_init(XDR * xdrs, XDR * rsp);

int
uc_rpc_xfer_run(XDR * xdrs, XDR * rsp);

int
uc_rpc_xfer_exit(XDR * xdrs, XDR * rsp);
