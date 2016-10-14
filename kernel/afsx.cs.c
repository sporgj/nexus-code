/* Machine generated file -- Do NOT edit */

#include "afsx.h"

#include <rx/rx.h>
#include <rx/rx_null.h>
#include "afsx_hdr.h"
#ifndef UCAFS_ENTRY_TYPE
#define UCAFS_ENTRY_TYPE
static bool_t xdr_ucafs_entry_type(XDR * xdrs, ucafs_entry_type * lp)
{
 // TODO no need to make the additional call_
 return xdr_afs_uint32(xdrs, (afs_uint32 *)lp);
}
#endif
#define AFSX_REQ_MAX 2
#define AFSX_REQ_MIN 1
#define AFSX_NULL 0
int AFSX_fversion(struct rx_connection *z_conn,int dummy,int * result)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 130;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_int(&z_xdrs, &dummy))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_int(&z_xdrs, result))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		0, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_create(struct rx_connection *z_conn,char * path,ucafs_entry_type type,char * *crypto_fname)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 131;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &path, AFSX_PATH_MAX))
	     || (!xdr_ucafs_entry_type(&z_xdrs, &type))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_string(&z_xdrs, crypto_fname, AFSX_FNAME_MAX))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		1, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_find(struct rx_connection *z_conn,char * fake_name,char * path,ucafs_entry_type type,char * *real_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 132;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fake_name, AFSX_FNAME_MAX))
	     || (!xdr_string(&z_xdrs, &path, AFSX_PATH_MAX))
	     || (!xdr_ucafs_entry_type(&z_xdrs, &type))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_string(&z_xdrs, real_name, AFSX_FNAME_MAX))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		2, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_lookup(struct rx_connection *z_conn,char * fpath,ucafs_entry_type type,char * *fake_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 133;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))
	     || (!xdr_ucafs_entry_type(&z_xdrs, &type))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_string(&z_xdrs, fake_name, AFSX_FNAME_MAX))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		3, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_remove(struct rx_connection *z_conn,char * fpath,ucafs_entry_type type,char * *code_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 134;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))
	     || (!xdr_ucafs_entry_type(&z_xdrs, &type))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_string(&z_xdrs, code_name, AFSX_FNAME_MAX))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		4, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_rename(struct rx_connection *z_conn,char * old_fpath,char * new_path,ucafs_entry_type type,char * *code_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 135;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &old_fpath, AFSX_PATH_MAX))
	     || (!xdr_string(&z_xdrs, &new_path, AFSX_PATH_MAX))
	     || (!xdr_ucafs_entry_type(&z_xdrs, &type))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_string(&z_xdrs, code_name, AFSX_FNAME_MAX))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		5, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_readwrite_start(struct rx_connection *z_conn,int op,char * fpath,afs_uint32 max_chunk_size,afs_uint32 total_size,afs_int32 * id)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 235;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_int(&z_xdrs, &op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))
	     || (!xdr_afs_uint32(&z_xdrs, &max_chunk_size))
	     || (!xdr_afs_uint32(&z_xdrs, &total_size))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_afs_int32(&z_xdrs, id))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		6, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int AFSX_readwrite_finish(struct rx_connection *z_conn,afs_int32 id)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 236;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_afs_int32(&z_xdrs, &id))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	z_result = rx_EndCall(z_call, z_result);
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_conn->peer,
		(((afs_uint32)(ntohs(z_conn->serviceId) << 16)) 
		| ((afs_uint32)ntohs(z_conn->peer->port))),
		7, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int StartAFSX_readwrite_data(struct rx_call *z_call,afs_int32 id,afs_uint32 size)
{
	static int z_op = 237;
	int z_result;
	XDR z_xdrs;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_afs_int32(&z_xdrs, &id))
	     || (!xdr_afs_uint32(&z_xdrs, &size))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	return z_result;
}

int EndAFSX_readwrite_data(struct rx_call *z_call,int * moredata)
{
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	/* Un-marshal the reply arguments */
	xdrrx_create(&z_xdrs, z_call, XDR_DECODE);
	if ((!xdr_int(&z_xdrs, moredata))) {
		z_result = RXGEN_CC_UNMARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_call->conn->peer,
		(((afs_uint32)(ntohs(z_call->conn->serviceId) << 16)) |
		((afs_uint32)ntohs(z_call->conn->peer->port))),
		8, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

