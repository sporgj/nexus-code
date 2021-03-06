/*
 * Copyright 2000, International Business Machines Corporation and others.
 * All Rights Reserved.
 * 
 * This software has been released under the terms of the IBM Public
 * License.  For details, see the LICENSE file in the top-level source
 * directory or online at http://www.openafs.org/dl/license10.html
 */

/*
 * rx_knet.c - RX kernel send, receive and timer routines.
 *
 * Linux implementation.
 */
#include <afsconfig.h>
#include "afs/param.h"


#include <linux/version.h>
#ifdef AFS_LINUX22_ENV
#include "rx/rx_kcommon.h"
#if defined(AFS_LINUX24_ENV)
#include "h/smp_lock.h"
#endif
#include <asm/uaccess.h>
#ifdef ADAPT_PMTU
#include <linux/errqueue.h>
#include <linux/icmp.h>
#endif

/* rxk_NewSocket
 * open and bind RX socket
 */
osi_socket *
rxk_NewSocketHost(afs_uint32 ahost, short aport)
{
    struct socket *sockp;
    struct sockaddr_in myaddr;
    int code;
    KERNEL_SPACE_DECL;
#ifdef ADAPT_PMTU
    int pmtu = IP_PMTUDISC_WANT;
    int do_recverr = 1;
#else
    int pmtu = IP_PMTUDISC_DONT;
#endif

    /* We need a better test for this. if you need it back, tell us
     * how to detect it. 
     */
#ifdef LINUX_KERNEL_SOCK_CREATE_V
    code = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sockp, 0);
#else
    code = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sockp);
#endif
    if (code < 0)
	return NULL;

    /* Bind socket */
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = ahost;
    myaddr.sin_port = aport;
    code =
	sockp->ops->bind(sockp, (struct sockaddr *)&myaddr, sizeof(myaddr));

    if (code < 0) {
#if defined(AFS_LINUX24_ENV)
	printk("sock_release(rx_socket) FIXME\n");
#else
	sock_release(sockp);
#endif
	return NULL;
    }

    TO_USER_SPACE();
    sockp->ops->setsockopt(sockp, SOL_IP, IP_MTU_DISCOVER, (char *)&pmtu,
                           sizeof(pmtu));
#ifdef ADAPT_PMTU
    sockp->ops->setsockopt(sockp, SOL_IP, IP_RECVERR, (char *)&do_recverr,
                           sizeof(do_recverr));
#endif
    TO_KERNEL_SPACE();
    return (osi_socket *)sockp;
}

osi_socket *
rxk_NewSocket(short aport)
{
    return rxk_NewSocketHost(htonl(INADDR_ANY), aport);
}

/* free socket allocated by osi_NetSocket */
int
rxk_FreeSocket(struct socket *asocket)
{
    AFS_STATCNT(osi_FreeSocket);
    return 0;
}

#ifdef ADAPT_PMTU
void
handle_socket_error(osi_socket so)
{
    KERNEL_SPACE_DECL;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sock_extended_err *err;
    struct sockaddr_in addr;
    struct sockaddr *offender;
    char *controlmsgbuf;
    int code;
    struct socket *sop = (struct socket *)so;

    if (!(controlmsgbuf=rxi_Alloc(256)))
	return;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;
    msg.msg_control = controlmsgbuf;
    msg.msg_controllen = 256;
    msg.msg_flags = 0;

    TO_USER_SPACE();
    code = sock_recvmsg(sop, &msg, 256, MSG_ERRQUEUE|MSG_DONTWAIT|MSG_TRUNC);
    TO_KERNEL_SPACE();

    if (code < 0 || !(msg.msg_flags & MSG_ERRQUEUE))
	goto out;

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	if (CMSG_OK(&msg, cmsg) && cmsg->cmsg_level == SOL_IP &&
	    cmsg->cmsg_type == IP_RECVERR)
	    break;
    }
    if (!cmsg)
	goto out;
    err = CMSG_DATA(cmsg);
    offender = SO_EE_OFFENDER(err);
    
    if (offender->sa_family != AF_INET)
       goto out;

    memcpy(&addr, offender, sizeof(addr));

    if (err->ee_origin == SO_EE_ORIGIN_ICMP &&
	err->ee_type == ICMP_DEST_UNREACH &&
	err->ee_code == ICMP_FRAG_NEEDED) {
	rxi_SetPeerMtu(NULL, ntohl(addr.sin_addr.s_addr), ntohs(addr.sin_port),
		       err->ee_info);
    }
    /* other DEST_UNREACH's and TIME_EXCEEDED should be dealt with too */

out:
    rxi_Free(controlmsgbuf, 256);
    return;
}
#endif

/* osi_NetSend
 *
 * Return codes:
 * 0 = success
 * non-zero = failure
 */
int
osi_NetSend(osi_socket sop, struct sockaddr_in *to, struct iovec *iovec,
	    int iovcnt, afs_int32 size, int istack)
{
    KERNEL_SPACE_DECL;
    struct msghdr msg;
    int code;
#ifdef ADAPT_PMTU
    int sockerr;
    size_t esize;

    while (1) {
	sockerr=0;
	esize = sizeof(sockerr);
	TO_USER_SPACE();
	sop->ops->getsockopt(sop, SOL_SOCKET, SO_ERROR, (char *)&sockerr,
			   &esize);
	TO_KERNEL_SPACE();
	if (sockerr == 0)
	   break;
	handle_socket_error(sop);
    }
#endif

    msg.msg_iovlen = iovcnt;
    msg.msg_iov = iovec;
    msg.msg_name = to;
    msg.msg_namelen = sizeof(*to);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    TO_USER_SPACE();
    code = sock_sendmsg(sop, &msg, size);
    TO_KERNEL_SPACE();
    return (code < 0) ? code : 0;
}


/* osi_NetReceive
 * OS dependent part of kernel RX listener thread.
 *
 * Arguments:
 *	so      socket to receive on, typically rx_socket
 *	from    pointer to a sockaddr_in. 
 *	iov     array of iovecs to fill in.
 *	iovcnt  how many iovecs there are.
 *	lengthp IN/OUT in: total space available in iovecs. out: size of read.
 *
 * Return
 * 0 if successful
 * error code (such as EINTER) if not
 *
 * Environment
 *	Note that the maximum number of iovecs is 2 + RX_MAXWVECS. This is
 *	so we have a little space to look for packets larger than 
 *	rx_maxReceiveSize.
 */
int rxk_lastSocketError;
int rxk_nSocketErrors;
int
osi_NetReceive(osi_socket so, struct sockaddr_in *from, struct iovec *iov,
	       int iovcnt, int *lengthp)
{
    KERNEL_SPACE_DECL;
    struct msghdr msg;
    int code;
#ifdef ADAPT_PMTU
    int sockerr;
    size_t esize;
#endif
    struct iovec tmpvec[RX_MAXWVECS + 2];
    struct socket *sop = (struct socket *)so;

    if (iovcnt > RX_MAXWVECS + 2) {
	osi_Panic("Too many (%d) iovecs passed to osi_NetReceive\n", iovcnt);
    }
#ifdef ADAPT_PMTU
    while (1) {
	sockerr=0;
	esize = sizeof(sockerr);
 	TO_USER_SPACE();
	sop->ops->getsockopt(sop, SOL_SOCKET, SO_ERROR, (char *)&sockerr,
			   &esize);
	TO_KERNEL_SPACE();
	if (sockerr == 0)
	   break;
	handle_socket_error(so);
    }
#endif
    memcpy(tmpvec, iov, iovcnt * sizeof(struct iovec));
    msg.msg_name = from;
    msg.msg_iov = tmpvec;
    msg.msg_iovlen = iovcnt;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    TO_USER_SPACE();
    code = sock_recvmsg(sop, &msg, *lengthp, 0);
    TO_KERNEL_SPACE();

    if (code < 0) {
	/* Clear the error before using the socket again.
	 * Oh joy, Linux has hidden header files as well. It appears we can
	 * simply call again and have it clear itself via sock_error().
	 */
#ifdef AFS_LINUX22_ENV
	flush_signals(current);	/* We don't want no stinkin' signals. */
#else
	current->signal = 0;	/* We don't want no stinkin' signals. */
#endif
	rxk_lastSocketError = code;
	rxk_nSocketErrors++;
    } else {
	*lengthp = code;
	code = 0;
    }

    return code;
}
#ifdef EXPORTED_TASKLIST_LOCK
extern rwlock_t tasklist_lock __attribute__((weak));
#endif
void
osi_StopListener(void)
{
    extern struct task_struct *rxk_ListenerTask;

    while (rxk_ListenerTask) {
        if (rxk_ListenerTask) {
	    flush_signals(rxk_ListenerTask);
	    force_sig(SIGKILL, rxk_ListenerTask);
	}
	if (!rxk_ListenerTask)
	    break;
	afs_osi_Sleep(&rxk_ListenerTask);
    }
    sock_release(rx_socket);
    rx_socket = NULL;
}

#endif /* AFS_LINUX22_ENV */
