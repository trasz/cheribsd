/*
 * System call prototypes.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from FreeBSD
 */

#ifndef _CHERIABI_PROTO_H_
#define	_CHERIABI_PROTO_H_

#include <sys/signal.h>
#include <sys/acl.h>
#include <sys/cpuset.h>
#include <sys/_ffcounter.h>
#include <sys/_semaphore.h>
#include <sys/ucontext.h>
#include <sys/wait.h>

#include <bsm/audit_kevents.h>

struct proc;

struct thread;

#define	PAD_(t)	(sizeof(register_t) <= sizeof(t) ? \
		0 : sizeof(register_t) - sizeof(t))

#if BYTE_ORDER == LITTLE_ENDIAN
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif
struct cheriabi_recvmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(struct msghdr_c *)]; struct msghdr_c * msg; char msg_r_[PADR_(struct msghdr_c *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sendmsg_args {
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char msg_l_[PADL_(struct msghdr_c *)]; struct msghdr_c * msg; char msg_r_[PADR_(struct msghdr_c *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_ioctl_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char com_l_[PADL_(u_long)]; u_long com; char com_r_[PADR_(u_long)];
	char data_l_[PADL_(caddr_t)]; caddr_t data; char data_r_[PADR_(caddr_t)];
};
struct cheriabi_execve_args {
	char fname_l_[PADL_(char *)]; char * fname; char fname_r_[PADR_(char *)];
	char argv_l_[PADL_(struct chericap *)]; struct chericap * argv; char argv_r_[PADR_(struct chericap *)];
	char envv_l_[PADL_(struct chericap *)]; struct chericap * envv; char envv_r_[PADR_(struct chericap *)];
};
struct cheriabi_readv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct cheriabi_writev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
};
struct cheriabi_ktimer_create_args {
	char clock_id_l_[PADL_(clockid_t)]; clockid_t clock_id; char clock_id_r_[PADR_(clockid_t)];
	char evp_l_[PADL_(struct sigevent_c *)]; struct sigevent_c * evp; char evp_r_[PADR_(struct sigevent_c *)];
	char timerid_l_[PADL_(int *)]; int * timerid; char timerid_r_[PADR_(int *)];
};
struct cheriabi_aio_read_args {
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_aio_write_args {
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_lio_listio_args {
	char mode_l_[PADL_(int)]; int mode; char mode_r_[PADR_(int)];
	char acb_list_l_[PADL_(struct aiocb_c *const *)]; struct aiocb_c *const * acb_list; char acb_list_r_[PADR_(struct aiocb_c *const *)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char sig_l_[PADL_(struct sigevent_c *)]; struct sigevent_c * sig; char sig_r_[PADR_(struct sigevent_c *)];
};
struct cheriabi_preadv_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_pwritev_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(u_int)]; u_int iovcnt; char iovcnt_r_[PADR_(u_int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
};
struct cheriabi_aio_return_args {
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_aio_suspend_args {
	char aiocbp_l_[PADL_(struct aiocb_c *const *)]; struct aiocb_c *const * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *const *)];
	char nent_l_[PADL_(int)]; int nent; char nent_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct cheriabi_aio_cancel_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_aio_error_args {
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_jail_args {
	char jail_l_[PADL_(struct jail_c *)]; struct jail_c * jail; char jail_r_[PADR_(struct jail_c *)];
};
struct cheriabi_sigtimedwait_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(siginfo_t *)]; siginfo_t * info; char info_r_[PADR_(siginfo_t *)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct cheriabi_sigwaitinfo_args {
	char set_l_[PADL_(const sigset_t *)]; const sigset_t * set; char set_r_[PADR_(const sigset_t *)];
	char info_l_[PADL_(siginfo_t *)]; siginfo_t * info; char info_r_[PADR_(siginfo_t *)];
};
struct cheriabi_aio_waitcomplete_args {
	char aiocbp_l_[PADL_(struct aiocb_c **)]; struct aiocb_c ** aiocbp; char aiocbp_r_[PADR_(struct aiocb_c **)];
	char timeout_l_[PADL_(struct timespec *)]; struct timespec * timeout; char timeout_r_[PADR_(struct timespec *)];
};
struct cheriabi_kevent_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char changelist_l_[PADL_(const struct kevent_c *)]; const struct kevent_c * changelist; char changelist_r_[PADR_(const struct kevent_c *)];
	char nchanges_l_[PADL_(int)]; int nchanges; char nchanges_r_[PADR_(int)];
	char eventlist_l_[PADL_(struct kevent_c *)]; struct kevent_c * eventlist; char eventlist_r_[PADR_(struct kevent_c *)];
	char nevents_l_[PADL_(int)]; int nevents; char nevents_r_[PADR_(int)];
	char timeout_l_[PADL_(const struct timespec *)]; const struct timespec * timeout; char timeout_r_[PADR_(const struct timespec *)];
};
struct cheriabi_nmount_args {
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sendfile_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char s_l_[PADL_(int)]; int s; char s_r_[PADR_(int)];
	char offset_l_[PADL_(off_t)]; off_t offset; char offset_r_[PADR_(off_t)];
	char nbytes_l_[PADL_(size_t)]; size_t nbytes; char nbytes_r_[PADR_(size_t)];
	char hdtr_l_[PADL_(struct sf_hdtr_c *)]; struct sf_hdtr_c * hdtr; char hdtr_r_[PADR_(struct sf_hdtr_c *)];
	char sbytes_l_[PADL_(off_t *)]; off_t * sbytes; char sbytes_r_[PADR_(off_t *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sigaction_args {
	char sig_l_[PADL_(int)]; int sig; char sig_r_[PADR_(int)];
	char act_l_[PADL_(struct sigaction_c *)]; struct sigaction_c * act; char act_r_[PADR_(struct sigaction_c *)];
	char oact_l_[PADL_(struct sigaction_c *)]; struct sigaction_c * oact; char oact_r_[PADR_(struct sigaction_c *)];
};
struct cheriabi_sigreturn_args {
	char sigcntxp_l_[PADL_(const struct ucontext_c *)]; const struct ucontext_c * sigcntxp; char sigcntxp_r_[PADR_(const struct ucontext_c *)];
};
struct cheriabi_getcontext_args {
	char ucp_l_[PADL_(struct ucontext_c *)]; struct ucontext_c * ucp; char ucp_r_[PADR_(struct ucontext_c *)];
};
struct cheriabi_setcontext_args {
	char ucp_l_[PADL_(const struct ucontext_c *)]; const struct ucontext_c * ucp; char ucp_r_[PADR_(const struct ucontext_c *)];
};
struct cheriabi_swapcontext_args {
	char oucp_l_[PADL_(struct ucontext_c *)]; struct ucontext_c * oucp; char oucp_r_[PADR_(struct ucontext_c *)];
	char ucp_l_[PADL_(const struct ucontext_c *)]; const struct ucontext_c * ucp; char ucp_r_[PADR_(const struct ucontext_c *)];
};
struct cheriabi_thr_new_args {
	char param_l_[PADL_(struct thr_param_c *)]; struct thr_param_c * param; char param_r_[PADR_(struct thr_param_c *)];
	char param_size_l_[PADL_(int)]; int param_size; char param_size_r_[PADR_(int)];
};
struct cheriabi_kmq_notify_args {
	char mqd_l_[PADL_(int)]; int mqd; char mqd_r_[PADR_(int)];
	char sigev_l_[PADL_(const struct sigevent *)]; const struct sigevent * sigev; char sigev_r_[PADR_(const struct sigevent *)];
};
struct cheriabi_aio_fsync_args {
	char op_l_[PADL_(int)]; int op; char op_r_[PADR_(int)];
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
struct cheriabi_sctp_generic_sendmsg_iov_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec_c *)]; struct iovec_c * iov; char iov_r_[PADR_(struct iovec_c *)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char to_l_[PADL_(caddr_t)]; caddr_t to; char to_r_[PADR_(caddr_t)];
	char tolen_l_[PADL_(__socklen_t)]; __socklen_t tolen; char tolen_r_[PADR_(__socklen_t)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo *)]; struct sctp_sndrcvinfo * sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo *)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_sctp_generic_recvmsg_args {
	char sd_l_[PADL_(int)]; int sd; char sd_r_[PADR_(int)];
	char iov_l_[PADL_(struct iovec_c *)]; struct iovec_c * iov; char iov_r_[PADR_(struct iovec_c *)];
	char iovlen_l_[PADL_(int)]; int iovlen; char iovlen_r_[PADR_(int)];
	char from_l_[PADL_(struct sockaddr *)]; struct sockaddr * from; char from_r_[PADR_(struct sockaddr *)];
	char fromlenaddr_l_[PADL_(__socklen_t *)]; __socklen_t * fromlenaddr; char fromlenaddr_r_[PADR_(__socklen_t *)];
	char sinfo_l_[PADL_(struct sctp_sndrcvinfo *)]; struct sctp_sndrcvinfo * sinfo; char sinfo_r_[PADR_(struct sctp_sndrcvinfo *)];
	char msg_flags_l_[PADL_(int *)]; int * msg_flags; char msg_flags_r_[PADR_(int *)];
};
struct cheriabi_fexecve_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char argv_l_[PADL_(struct chericap *)]; struct chericap * argv; char argv_r_[PADR_(struct chericap *)];
	char envv_l_[PADL_(struct chericap *)]; struct chericap * envv; char envv_r_[PADR_(struct chericap *)];
};
struct cheriabi_jail_get_args {
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_jail_set_args {
	char iovp_l_[PADL_(struct iovec_c *)]; struct iovec_c * iovp; char iovp_r_[PADR_(struct iovec_c *)];
	char iovcnt_l_[PADL_(unsigned int)]; unsigned int iovcnt; char iovcnt_r_[PADR_(unsigned int)];
	char flags_l_[PADL_(int)]; int flags; char flags_r_[PADR_(int)];
};
struct cheriabi_semctl_args {
	char semid_l_[PADL_(int)]; int semid; char semid_r_[PADR_(int)];
	char semnum_l_[PADL_(int)]; int semnum; char semnum_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char arg_l_[PADL_(union semun_c *)]; union semun_c * arg; char arg_r_[PADR_(union semun_c *)];
};
struct cheriabi_msgctl_args {
	char msqid_l_[PADL_(int)]; int msqid; char msqid_r_[PADR_(int)];
	char cmd_l_[PADL_(int)]; int cmd; char cmd_r_[PADR_(int)];
	char buf_l_[PADL_(struct msqid_ds_c *)]; struct msqid_ds_c * buf; char buf_r_[PADR_(struct msqid_ds_c *)];
};
struct cheriabi_cap_enter_args {
	register_t dummy;
};
struct cheriabi_wait6_args {
	char idtype_l_[PADL_(int)]; int idtype; char idtype_r_[PADR_(int)];
	char id_l_[PADL_(id_t)]; id_t id; char id_r_[PADR_(id_t)];
	char status_l_[PADL_(int *)]; int * status; char status_r_[PADR_(int *)];
	char options_l_[PADL_(int)]; int options; char options_r_[PADR_(int)];
	char wrusage_l_[PADL_(struct __wrusage *)]; struct __wrusage * wrusage; char wrusage_r_[PADR_(struct __wrusage *)];
	char info_l_[PADL_(struct __siginfo_c *)]; struct __siginfo_c * info; char info_r_[PADR_(struct __siginfo_c *)];
};
struct cheriabi_cap_ioctls_limit_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(const struct chericap *)]; const struct chericap * cmds; char cmds_r_[PADR_(const struct chericap *)];
	char ncmds_l_[PADL_(size_t)]; size_t ncmds; char ncmds_r_[PADR_(size_t)];
};
struct cheriabi_cap_ioctls_get_args {
	char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
	char cmds_l_[PADL_(struct chericap *)]; struct chericap * cmds; char cmds_r_[PADR_(struct chericap *)];
	char maxcmds_l_[PADL_(size_t)]; size_t maxcmds; char maxcmds_r_[PADR_(size_t)];
};
struct cheriabi_aio_mlock_args {
	char aiocbp_l_[PADL_(struct aiocb_c *)]; struct aiocb_c * aiocbp; char aiocbp_r_[PADR_(struct aiocb_c *)];
};
#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif
int	cheriabi_recvmsg(struct thread *, struct cheriabi_recvmsg_args *);
int	cheriabi_sendmsg(struct thread *, struct cheriabi_sendmsg_args *);
int	cheriabi_ioctl(struct thread *, struct cheriabi_ioctl_args *);
int	cheriabi_execve(struct thread *, struct cheriabi_execve_args *);
int	cheriabi_readv(struct thread *, struct cheriabi_readv_args *);
int	cheriabi_writev(struct thread *, struct cheriabi_writev_args *);
int	cheriabi_ktimer_create(struct thread *, struct cheriabi_ktimer_create_args *);
int	cheriabi_aio_read(struct thread *, struct cheriabi_aio_read_args *);
int	cheriabi_aio_write(struct thread *, struct cheriabi_aio_write_args *);
int	cheriabi_lio_listio(struct thread *, struct cheriabi_lio_listio_args *);
int	cheriabi_preadv(struct thread *, struct cheriabi_preadv_args *);
int	cheriabi_pwritev(struct thread *, struct cheriabi_pwritev_args *);
int	cheriabi_aio_return(struct thread *, struct cheriabi_aio_return_args *);
int	cheriabi_aio_suspend(struct thread *, struct cheriabi_aio_suspend_args *);
int	cheriabi_aio_cancel(struct thread *, struct cheriabi_aio_cancel_args *);
int	cheriabi_aio_error(struct thread *, struct cheriabi_aio_error_args *);
int	cheriabi_jail(struct thread *, struct cheriabi_jail_args *);
int	cheriabi_sigtimedwait(struct thread *, struct cheriabi_sigtimedwait_args *);
int	cheriabi_sigwaitinfo(struct thread *, struct cheriabi_sigwaitinfo_args *);
int	cheriabi_aio_waitcomplete(struct thread *, struct cheriabi_aio_waitcomplete_args *);
int	cheriabi_kevent(struct thread *, struct cheriabi_kevent_args *);
int	cheriabi_nmount(struct thread *, struct cheriabi_nmount_args *);
int	cheriabi_sendfile(struct thread *, struct cheriabi_sendfile_args *);
int	cheriabi_sigaction(struct thread *, struct cheriabi_sigaction_args *);
int	cheriabi_sigreturn(struct thread *, struct cheriabi_sigreturn_args *);
int	cheriabi_getcontext(struct thread *, struct cheriabi_getcontext_args *);
int	cheriabi_setcontext(struct thread *, struct cheriabi_setcontext_args *);
int	cheriabi_swapcontext(struct thread *, struct cheriabi_swapcontext_args *);
int	cheriabi_thr_new(struct thread *, struct cheriabi_thr_new_args *);
int	cheriabi_kmq_notify(struct thread *, struct cheriabi_kmq_notify_args *);
int	cheriabi_aio_fsync(struct thread *, struct cheriabi_aio_fsync_args *);
int	cheriabi_sctp_generic_sendmsg_iov(struct thread *, struct cheriabi_sctp_generic_sendmsg_iov_args *);
int	cheriabi_sctp_generic_recvmsg(struct thread *, struct cheriabi_sctp_generic_recvmsg_args *);
int	cheriabi_fexecve(struct thread *, struct cheriabi_fexecve_args *);
int	cheriabi_jail_get(struct thread *, struct cheriabi_jail_get_args *);
int	cheriabi_jail_set(struct thread *, struct cheriabi_jail_set_args *);
int	cheriabi_semctl(struct thread *, struct cheriabi_semctl_args *);
int	cheriabi_msgctl(struct thread *, struct cheriabi_msgctl_args *);
int	cheriabi_cap_enter(struct thread *, struct cheriabi_cap_enter_args *);
int	cheriabi_wait6(struct thread *, struct cheriabi_wait6_args *);
int	cheriabi_cap_ioctls_limit(struct thread *, struct cheriabi_cap_ioctls_limit_args *);
int	cheriabi_cap_ioctls_get(struct thread *, struct cheriabi_cap_ioctls_get_args *);
int	cheriabi_aio_mlock(struct thread *, struct cheriabi_aio_mlock_args *);

#ifdef COMPAT_43

#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif

#endif /* COMPAT_43 */


#ifdef COMPAT_FREEBSD4

#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif

#endif /* COMPAT_FREEBSD4 */


#ifdef COMPAT_FREEBSD6

#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif

#endif /* COMPAT_FREEBSD6 */


#ifdef COMPAT_FREEBSD7

#if !defined(PAD64_REQUIRED) && (defined(__powerpc__) || defined(__mips__))
#define PAD64_REQUIRED
#endif

#endif /* COMPAT_FREEBSD7 */

#define	CHERIABI_SYS_AUE_cheriabi_recvmsg	AUE_RECVMSG
#define	CHERIABI_SYS_AUE_cheriabi_sendmsg	AUE_SENDMSG
#define	CHERIABI_SYS_AUE_cheriabi_ioctl	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_execve	AUE_EXECVE
#define	CHERIABI_SYS_AUE_cheriabi_readv	AUE_READV
#define	CHERIABI_SYS_AUE_cheriabi_writev	AUE_WRITEV
#define	CHERIABI_SYS_AUE_cheriabi_ktimer_create	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_read	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_write	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_lio_listio	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_preadv	AUE_PREADV
#define	CHERIABI_SYS_AUE_cheriabi_pwritev	AUE_PWRITEV
#define	CHERIABI_SYS_AUE_cheriabi_aio_return	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_suspend	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_cancel	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_error	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_jail	AUE_JAIL
#define	CHERIABI_SYS_AUE_cheriabi_sigtimedwait	AUE_SIGWAIT
#define	CHERIABI_SYS_AUE_cheriabi_sigwaitinfo	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_waitcomplete	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kevent	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_nmount	AUE_NMOUNT
#define	CHERIABI_SYS_AUE_cheriabi_sendfile	AUE_SENDFILE
#define	CHERIABI_SYS_AUE_cheriabi_sigaction	AUE_SIGACTION
#define	CHERIABI_SYS_AUE_cheriabi_sigreturn	AUE_SIGRETURN
#define	CHERIABI_SYS_AUE_cheriabi_getcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_setcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_swapcontext	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_thr_new	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_kmq_notify	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_aio_fsync	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sctp_generic_sendmsg_iov	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_sctp_generic_recvmsg	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_fexecve	AUE_FEXECVE
#define	CHERIABI_SYS_AUE_cheriabi_jail_get	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_jail_set	AUE_NULL
#define	CHERIABI_SYS_AUE_cheriabi_semctl	AUE_SEMCTL
#define	CHERIABI_SYS_AUE_cheriabi_msgctl	AUE_MSGCTL
#define	CHERIABI_SYS_AUE_cheriabi_cap_enter	AUE_CAP_ENTER
#define	CHERIABI_SYS_AUE_cheriabi_wait6	AUE_WAIT6
#define	CHERIABI_SYS_AUE_cheriabi_cap_ioctls_limit	AUE_CAP_IOCTLS_LIMIT
#define	CHERIABI_SYS_AUE_cheriabi_cap_ioctls_get	AUE_CAP_IOCTLS_GET
#define	CHERIABI_SYS_AUE_cheriabi_aio_mlock	AUE_NULL

#undef PAD_
#undef PADL_
#undef PADR_

#endif /* !_CHERIABI_PROTO_H_ */
