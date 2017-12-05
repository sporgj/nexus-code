/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 *
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

#ifndef	_XDR_PROTOTYPES_H
#define _XDR_PROTOTYPES_H

/* xdr.c */
extern bool_t xdr_void(void);
extern bool_t xdr_long(XDR * xdrs, long *lp);
extern bool_t xdr_u_long(XDR * xdrs, u_long * ulp);
extern bool_t xdr_int(XDR * xdrs, int *ip);
extern bool_t xdr_u_int(XDR * xdrs, u_int * up);
extern bool_t xdr_char(XDR * xdrs, char *sp);
extern bool_t xdr_u_char(XDR * xdrs, u_char * usp);
extern bool_t xdr_short(XDR * xdrs, short *sp);
extern bool_t xdr_u_short(XDR * xdrs, u_short * usp);
extern bool_t xdr_bool(XDR * xdrs, bool_t * bp);
extern bool_t xdr_enum(XDR * xdrs, enum_t * ep);
extern bool_t xdr_opaque(XDR * xdrs, caddr_t cp, u_int cnt);
extern bool_t xdr_bytes(XDR * xdrs, char **cpp,
			u_int * sizep, u_int maxsize);
extern bool_t xdr_union(XDR * xdrs, enum_t * dscmp, caddr_t unp,
			struct xdr_discrim *choices, xdrproc_t dfault);
extern bool_t xdr_string(XDR * xdrs, char **cpp, u_int maxsize);
extern bool_t xdr_wrapstring(XDR * xdrs, char **cpp);
extern void * xdr_alloc(afs_int32 size);
extern void   xdr_free(xdrproc_t proc, void *obj);

/* xdr_len.c */
extern void xdrlen_create(XDR *xdrs);

/* xdr_mem.c */
extern void xdrmem_create(XDR * xdrs, caddr_t addr, u_int size,
			  enum xdr_op op);

#ifndef osi_alloc
extern char *osi_alloc(afs_int32 x);
#endif
#ifndef osi_free
extern int osi_free(char *x, afs_int32 size);
#endif
#endif /* _XDR_PROTOTYPES_H */
