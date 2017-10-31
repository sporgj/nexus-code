#include <stdint.h>

#include "afs.h"
#include "xdr.h"
#include "xdr_prototypes.h"


int
rpc_ping(XDR * xdrs, XDR * rsp);

int
rpc_dirops(afs_op_type_t msg_type, XDR * xdrs, XDR * rsp);

int
rpc_symlink(XDR * xdrs, XDR * rsp);

int
rpc_hardlink(XDR * xdrs, XDR * rsp);

int
rpc_rename(XDR * xdrs, XDR * rsp);

int
rpc_storeacl(XDR * xdrs, XDR * xdr_out);

int
rpc_xfer_init(XDR * xdrs, XDR * rsp);

int
rpc_xfer_run(XDR * xdrs, XDR * rsp);

int
rpc_xfer_exit(XDR * xdrs, XDR * rsp);
