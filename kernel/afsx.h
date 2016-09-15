/* Machine generated file -- Do NOT edit */

#ifndef	_RXGEN_AFSX_
#define	_RXGEN_AFSX_

#ifdef	KERNEL
/* The following 'ifndefs' are not a good solution to the vendor's omission of surrounding all system includes with 'ifndef's since it requires that this file is included after the system includes...*/
#include <afsconfig.h>
#include "afs/param.h"
#ifdef	UKERNEL
#include "afs/sysincludes.h"
#include "rx/xdr.h"
#include "rx/rx.h"
#include "rx/rx_globals.h"
#else	/* UKERNEL */
#include "h/types.h"
#ifndef	SOCK_DGRAM  /* XXXXX */
#include "h/socket.h"
#endif
struct ubik_client;
#ifndef	DTYPE_SOCKET  /* XXXXX */
#ifndef AFS_LINUX22_ENV
#include "h/file.h"
#endif
#endif
#ifndef	S_IFMT  /* XXXXX */
#include "h/stat.h"
#endif
#if defined (AFS_OBSD_ENV) && !defined (MLEN)
#include "sys/mbuf.h"
#endif
#ifndef	IPPROTO_UDP /* XXXXX */
#include "netinet/in.h"
#endif
#ifndef	DST_USA  /* XXXXX */
#include "h/time.h"
#endif
#ifndef AFS_LINUX22_ENV
#include "rpc/types.h"
#endif /* AFS_LINUX22_ENV */
#ifndef	XDR_GETLONG /* XXXXX */
#ifdef AFS_LINUX22_ENV
#ifndef quad_t
#define quad_t __quad_t
#define u_quad_t __u_quad_t
#endif
#endif
#include "rx/xdr.h"
#endif /* XDR_GETLONG */
#endif   /* UKERNEL */
#include "afs/rxgen_consts.h"
#include "afs_osi.h"
#include "rx/rx.h"
#include "rx/rx_globals.h"
#else	/* KERNEL */
#include <afs/param.h>
#include <afs/stds.h>
#include <sys/types.h>
#include <rx/xdr.h>
#include <rx/rx.h>
#include <rx/rx_globals.h>
#include <afs/rxgen_consts.h>
#endif	/* KERNEL */

#ifdef AFS_NT40_ENV
#ifndef AFS_RXGEN_EXPORT
#define AFS_RXGEN_EXPORT __declspec(dllimport)
#endif /* AFS_RXGEN_EXPORT */
#else /* AFS_NT40_ENV */
#define AFS_RXGEN_EXPORT
#endif /* AFS_NT40_ENV */

#include <rx/rx.h>
#include <rx/rx_null.h>
#include "afsx_hdr.h"
#define AFSX_REQ_MAX 2
#define AFSX_REQ_MIN 1
#define AFSX_NULL 0

extern int AFSX_fversion(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ int dummy,
	/*OUT*/ int * result);

extern afs_int32 SAFSX_fversion(
	/*IN */ struct rx_call *z_call,
	/*IN */ int dummy,
	/*OUT*/ int * result);

extern int AFSX_create(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ char * path,
	/*IN */ afs_int32 file_or_dir,
	/*OUT*/ char * *crypto_fname);

extern afs_int32 SAFSX_create(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * path,
	/*IN */ afs_int32 file_or_dir,
	/*OUT*/ char * *crypto_fname);

extern int AFSX_frealname(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ char * fake_name,
	/*IN */ char * path,
	/*OUT*/ char * *real_name);

extern afs_int32 SAFSX_frealname(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * fake_name,
	/*IN */ char * path,
	/*OUT*/ char * *real_name);

extern int AFSX_fencodename(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ char * fpath,
	/*OUT*/ char * *fake_name);

extern afs_int32 SAFSX_fencodename(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * fpath,
	/*OUT*/ char * *fake_name);

extern int AFSX_fremove(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ char * fpath,
	/*OUT*/ char * *code_name);

extern afs_int32 SAFSX_fremove(
	/*IN */ struct rx_call *z_call,
	/*IN */ char * fpath,
	/*OUT*/ char * *code_name);

extern int AFSX_readwrite_start(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ int op,
	/*IN */ char * fpath,
	/*IN */ afs_uint32 max_chunk_size,
	/*IN */ afs_uint32 total_size,
	/*OUT*/ afs_uint32 * id,
	/*OUT*/ afs_uint32 * padded_len);

extern afs_int32 SAFSX_readwrite_start(
	/*IN */ struct rx_call *z_call,
	/*IN */ int op,
	/*IN */ char * fpath,
	/*IN */ afs_uint32 max_chunk_size,
	/*IN */ afs_uint32 total_size,
	/*OUT*/ afs_uint32 * id,
	/*OUT*/ afs_uint32 * padded_len);

extern int AFSX_readwrite_finish(
	/*IN */ struct rx_connection *z_conn,
	/*IN */ int id);

extern afs_int32 SAFSX_readwrite_finish(
	/*IN */ struct rx_call *z_call,
	/*IN */ int id);

extern int StartAFSX_readwrite_data(
	/*IN */ struct rx_call *z_call,
	/*IN */ afs_uint32 id,
	/*IN */ afs_uint32 size);

extern int EndAFSX_readwrite_data(
	/*IN */ struct rx_call *z_call,
	/*OUT*/ int * moredata);

extern afs_int32 SAFSX_readwrite_data(
	/*IN */ struct rx_call *z_call,
	/*IN */ afs_uint32 id,
	/*IN */ afs_uint32 size,
	/*OUT*/ int * moredata);

extern int AFSX_ExecuteRequest(struct rx_call *);

/* Opcode-related useful stats for package: AFSX_ */
#define AFSX_LOWEST_OPCODE   1
#define AFSX_HIGHEST_OPCODE	8
#define AFSX_NUMBER_OPCODES	8

#define AFSX_NO_OF_STAT_FUNCS	8

AFS_RXGEN_EXPORT
extern const char *AFSX_function_names[];

#endif	/* _RXGEN_AFSX_ */
