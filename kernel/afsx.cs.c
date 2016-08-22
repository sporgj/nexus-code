/* Machine generated file -- Do NOT edit */

#include "afsx.h"

#include <rx/rx.h>
#include <rx/rx_null.h>
#define AFSX_SERVER_PORT 9462
#define AFSX_SERVICE_PORT 0
#define AFSX_SERVICE_ID 4
#define AFSX_STATUS_SUCCESS 0
#define AFSX_STATUS_ERROR 1
#define AFSX_STATUS_NOOP 2
#define AFSX_PACKET_SIZE 4096
#define AFSX_REQ_MAX 2
#define AFSX_REQ_MIN 1
#define AFSX_NULL 0
#define AFSX_FNAME_MAX 256
#define AFSX_PATH_MAX 1024
int AFSX_fversion(struct rx_connection *z_conn,int dummy,int * result)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 1;
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

int AFSX_fnew(struct rx_connection *z_conn,char * path,char * *crypto_fname)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 2;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &path, AFSX_PATH_MAX))) {
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

int AFSX_frealname(struct rx_connection *z_conn,char * fake_name,char * path,char * *real_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 3;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fake_name, AFSX_FNAME_MAX))
	     || (!xdr_string(&z_xdrs, &path, AFSX_PATH_MAX))) {
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

int AFSX_fencodename(struct rx_connection *z_conn,char * fpath,char * *fake_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 4;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))) {
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

int AFSX_fremove(struct rx_connection *z_conn,char * fpath,char * *code_name)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 5;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))) {
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

int AFSX_start_upload(struct rx_connection *z_conn,char * fpath,afs_uint32 max_chunk_size,afs_uint64 total_size,afs_uint32 * upload_id)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 6;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_string(&z_xdrs, &fpath, AFSX_PATH_MAX))
	     || (!xdr_afs_uint32(&z_xdrs, &max_chunk_size))
	     || (!xdr_afs_uint64(&z_xdrs, &total_size))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	/* Un-marshal the reply arguments */
	z_xdrs.x_op = XDR_DECODE;
	if ((!xdr_afs_uint32(&z_xdrs, upload_id))) {
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

int AFSX_end_upload(struct rx_connection *z_conn,int upload_id)
{
	struct rx_call *z_call = rx_NewCall(z_conn);
	static int z_op = 7;
	int z_result;
	XDR z_xdrs;
	struct clock __QUEUE, __EXEC;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_int(&z_xdrs, &upload_id))) {
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
		6, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

int StartAFSX_upload_file(struct rx_call *z_call,afs_uint32 upload_id,afs_uint32 chunk_size)
{
	static int z_op = 8;
	int z_result;
	XDR z_xdrs;
	xdrrx_create(&z_xdrs, z_call, XDR_ENCODE);

	/* Marshal the arguments */
	if ((!xdr_int(&z_xdrs, &z_op))
	     || (!xdr_afs_uint32(&z_xdrs, &upload_id))
	     || (!xdr_afs_uint32(&z_xdrs, &chunk_size))) {
		z_result = RXGEN_CC_MARSHAL;
		goto fail;
	}

	z_result = RXGEN_SUCCESS;
fail:
	return z_result;
}

int EndAFSX_upload_file(struct rx_call *z_call)
{
	int z_result;
	struct clock __QUEUE, __EXEC;
	z_result = RXGEN_SUCCESS;
	if (rx_enable_stats) {
	    clock_GetTime(&__EXEC);
	    clock_Sub(&__EXEC, &z_call->startTime);
	    __QUEUE = z_call->startTime;
	    clock_Sub(&__QUEUE, &z_call->queueTime);
	    rx_IncrementTimeAndCount(z_call->conn->peer,
		(((afs_uint32)(ntohs(z_call->conn->serviceId) << 16)) |
		((afs_uint32)ntohs(z_call->conn->peer->port))),
		7, AFSX_NO_OF_STAT_FUNCS, &__QUEUE, &__EXEC,
		&z_call->bytesSent, &z_call->bytesRcvd, 1);
	}

	return z_result;
}

