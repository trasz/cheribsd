/*
 * System call argument map.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * $FreeBSD$
 * created from FreeBSD
 */

#ifndef _CHERIABI_SYSARGMAP_H_
#define	_CHERIABI_SYSARGMAP_H_

struct {
	u_char sam_return_ptr;
	u_char sam_ptrmask;
} CHERIABI_SYS_argmap[CHERIABI_SYS_MAXSYSCALL] = {
	[CHERIABI_SYS_exit] = {
	},
	[CHERIABI_SYS_read] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_write] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_open] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_close] = {
	},
	[CHERIABI_SYS_wait4] = {
		.sam_ptrmask = 0x2 | 0x8
	},
	[CHERIABI_SYS_link] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_unlink] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_chdir] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_fchdir] = {
	},
	[CHERIABI_SYS_mknod] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_chmod] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_chown] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_mount] = {
		.sam_ptrmask = 0x1 | 0x2 | 0x8
	},
	[CHERIABI_SYS_unmount] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setuid] = {
	},
	[CHERIABI_SYS_ptrace] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_cheriabi_recvmsg] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_sendmsg] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_recvfrom] = {
		.sam_ptrmask = 0x2 | 0x10 | 0x20
	},
	[CHERIABI_SYS_accept] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_getpeername] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_getsockname] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_access] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_chflags] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_fchflags] = {
	},
	[CHERIABI_SYS_kill] = {
	},
	[CHERIABI_SYS_dup] = {
	},
	[CHERIABI_SYS_profil] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ktrace] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_getlogin] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setlogin] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_acct] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sigaltstack] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_cheriabi_ioctl] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_reboot] = {
	},
	[CHERIABI_SYS_revoke] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_symlink] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_readlink] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_cheriabi_execve] = {
		.sam_ptrmask = 0x1 | 0x2 | 0x4
	},
	[CHERIABI_SYS_umask] = {
	},
	[CHERIABI_SYS_chroot] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_msync] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_vadvise] = {
	},
	[CHERIABI_SYS_munmap] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_mprotect] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_madvise] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_mincore] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_getgroups] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_setgroups] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_setpgid] = {
	},
	[CHERIABI_SYS_setitimer] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_swapon] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_getitimer] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_dup2] = {
	},
	[CHERIABI_SYS_fcntl] = {
	},
	[CHERIABI_SYS_select] = {
		.sam_ptrmask = 0x2 | 0x4 | 0x8 | 0x10
	},
	[CHERIABI_SYS_fsync] = {
	},
	[CHERIABI_SYS_setpriority] = {
	},
	[CHERIABI_SYS_socket] = {
	},
	[CHERIABI_SYS_connect] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_getpriority] = {
	},
	[CHERIABI_SYS_bind] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_setsockopt] = {
		.sam_ptrmask = 0x8
	},
	[CHERIABI_SYS_listen] = {
	},
	[CHERIABI_SYS_gettimeofday] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_getrusage] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_getsockopt] = {
		.sam_ptrmask = 0x8 | 0x10
	},
	[CHERIABI_SYS_cheriabi_readv] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_writev] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_settimeofday] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_fchown] = {
	},
	[CHERIABI_SYS_fchmod] = {
	},
	[CHERIABI_SYS_setreuid] = {
	},
	[CHERIABI_SYS_setregid] = {
	},
	[CHERIABI_SYS_rename] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_flock] = {
	},
	[CHERIABI_SYS_mkfifo] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sendto] = {
		.sam_ptrmask = 0x2 | 0x10
	},
	[CHERIABI_SYS_shutdown] = {
	},
	[CHERIABI_SYS_socketpair] = {
		.sam_ptrmask = 0x8
	},
	[CHERIABI_SYS_mkdir] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_rmdir] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_utimes] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_adjtime] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_quotactl] = {
		.sam_ptrmask = 0x1 | 0x8
	},
	[CHERIABI_SYS_getfh] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_sysarch] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_rtprio] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_semsys] = {
	},
	[CHERIABI_SYS_msgsys] = {
	},
	[CHERIABI_SYS_shmsys] = {
	},
	[CHERIABI_SYS_ntp_adjtime] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setgid] = {
	},
	[CHERIABI_SYS_setegid] = {
	},
	[CHERIABI_SYS_seteuid] = {
	},
	[CHERIABI_SYS_stat] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_fstat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_lstat] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_pathconf] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_fpathconf] = {
	},
	[CHERIABI_SYS_getrlimit] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_setrlimit] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_getdirentries] = {
		.sam_ptrmask = 0x2 | 0x8
	},
	[CHERIABI_SYS___sysctl] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8 | 0x10
	},
	[CHERIABI_SYS_mlock] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_munlock] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_undelete] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_futimes] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_getpgid] = {
	},
	[CHERIABI_SYS_poll] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_semget] = {
	},
	[CHERIABI_SYS_semop] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_msgget] = {
	},
	[CHERIABI_SYS_msgsnd] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_msgrcv] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_shmat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_shmdt] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_shmget] = {
	},
	[CHERIABI_SYS_clock_gettime] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_clock_settime] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_clock_getres] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_ktimer_create] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_ktimer_delete] = {
	},
	[CHERIABI_SYS_ktimer_settime] = {
		.sam_ptrmask = 0x4 | 0x8
	},
	[CHERIABI_SYS_ktimer_gettime] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_ktimer_getoverrun] = {
	},
	[CHERIABI_SYS_nanosleep] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_ffclock_getcounter] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ffclock_setestimate] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ffclock_getestimate] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_clock_getcpuclockid2] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_minherit] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_rfork] = {
	},
	[CHERIABI_SYS_openbsd_poll] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_lchown] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_aio_read] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_aio_write] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_lio_listio] = {
		.sam_ptrmask = 0x2 | 0x8
	},
	[CHERIABI_SYS_getdents] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_lchmod] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_netbsd_lchown] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_lutimes] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_netbsd_msync] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_nstat] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_nfstat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_nlstat] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_cheriabi_preadv] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_pwritev] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_fhopen] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_fhstat] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_modnext] = {
	},
	[CHERIABI_SYS_modstat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_modfnext] = {
	},
	[CHERIABI_SYS_modfind] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_kldload] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_kldunload] = {
	},
	[CHERIABI_SYS_kldfind] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_kldnext] = {
	},
	[CHERIABI_SYS_kldstat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_kldfirstmod] = {
	},
	[CHERIABI_SYS_getsid] = {
	},
	[CHERIABI_SYS_setresuid] = {
	},
	[CHERIABI_SYS_setresgid] = {
	},
	[CHERIABI_SYS_cheriabi_aio_return] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_aio_suspend] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_cheriabi_aio_cancel] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_aio_error] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_mlockall] = {
	},
	[CHERIABI_SYS___getcwd] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sched_setparam] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_sched_getparam] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_sched_setscheduler] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_sched_getscheduler] = {
	},
	[CHERIABI_SYS_sched_get_priority_max] = {
	},
	[CHERIABI_SYS_sched_get_priority_min] = {
	},
	[CHERIABI_SYS_sched_rr_get_interval] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_utrace] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_kldsym] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_cheriabi_jail] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sigprocmask] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_sigsuspend] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sigpending] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_sigtimedwait] = {
		.sam_ptrmask = 0x1 | 0x2 | 0x4
	},
	[CHERIABI_SYS_cheriabi_sigwaitinfo] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS___acl_get_file] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS___acl_set_file] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS___acl_get_fd] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS___acl_set_fd] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS___acl_delete_file] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS___acl_delete_fd] = {
	},
	[CHERIABI_SYS___acl_aclcheck_file] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS___acl_aclcheck_fd] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_extattrctl] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x10
	},
	[CHERIABI_SYS_extattr_set_file] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_get_file] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_delete_file] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_cheriabi_aio_waitcomplete] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_getresuid] = {
		.sam_ptrmask = 0x1 | 0x2 | 0x4
	},
	[CHERIABI_SYS_getresgid] = {
		.sam_ptrmask = 0x1 | 0x2 | 0x4
	},
	[CHERIABI_SYS_cheriabi_kevent] = {
		.sam_ptrmask = 0x2 | 0x8 | 0x20
	},
	[CHERIABI_SYS_extattr_set_fd] = {
		.sam_ptrmask = 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_get_fd] = {
		.sam_ptrmask = 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_delete_fd] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS___setugid] = {
	},
	[CHERIABI_SYS_eaccess] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_nmount] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_kenv] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_lchflags] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_uuidgen] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_sendfile] = {
		.sam_ptrmask = 0x10 | 0x20
	},
	[CHERIABI_SYS_getfsstat] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_statfs] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_fstatfs] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_fhstatfs] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_ksem_close] = {
	},
	[CHERIABI_SYS_ksem_post] = {
	},
	[CHERIABI_SYS_ksem_wait] = {
	},
	[CHERIABI_SYS_ksem_trywait] = {
	},
	[CHERIABI_SYS_ksem_init] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ksem_open] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_ksem_unlink] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ksem_getvalue] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_ksem_destroy] = {
	},
	[CHERIABI_SYS_extattr_set_link] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_get_link] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8
	},
	[CHERIABI_SYS_extattr_delete_link] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_cheriabi_sigaction] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_cheriabi_sigreturn] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_getcontext] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_setcontext] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_swapcontext] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS___acl_get_link] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS___acl_set_link] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS___acl_delete_link] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS___acl_aclcheck_link] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_sigwait] = {
		.sam_ptrmask = 0x1 | 0x2
	},
	[CHERIABI_SYS_thr_exit] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_thr_self] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_thr_kill] = {
	},
	[CHERIABI_SYS_jail_attach] = {
	},
	[CHERIABI_SYS_extattr_list_fd] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_extattr_list_file] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_extattr_list_link] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_ksem_timedwait] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_thr_suspend] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_thr_wake] = {
	},
	[CHERIABI_SYS_kldunloadf] = {
	},
	[CHERIABI_SYS_audit] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_auditon] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_getauid] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setauid] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_getaudit] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setaudit] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_getaudit_addr] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setaudit_addr] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_auditctl] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS__umtx_op] = {
		.sam_ptrmask = 0x1 | 0x8 | 0x10
	},
	[CHERIABI_SYS_cheriabi_thr_new] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_sigqueue] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_kmq_open] = {
		.sam_ptrmask = 0x1 | 0x8
	},
	[CHERIABI_SYS_kmq_setattr] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_kmq_timedreceive] = {
		.sam_ptrmask = 0x2 | 0x8 | 0x10
	},
	[CHERIABI_SYS_kmq_timedsend] = {
		.sam_ptrmask = 0x2 | 0x10
	},
	[CHERIABI_SYS_cheriabi_kmq_notify] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_kmq_unlink] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_abort2] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_thr_set_name] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_aio_fsync] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_rtprio_thread] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_sctp_peeloff] = {
	},
	[CHERIABI_SYS_sctp_generic_sendmsg] = {
		.sam_ptrmask = 0x2 | 0x8 | 0x20
	},
	[CHERIABI_SYS_cheriabi_sctp_generic_sendmsg_iov] = {
		.sam_ptrmask = 0x2 | 0x8 | 0x20
	},
	[CHERIABI_SYS_cheriabi_sctp_generic_recvmsg] = {
		.sam_ptrmask = 0x2 | 0x8 | 0x10 | 0x20 | 0x40
	},
	[CHERIABI_SYS_pread] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_pwrite] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_mmap] = {
		.sam_return_ptr = 1,
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_lseek] = {
	},
	[CHERIABI_SYS_truncate] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_ftruncate] = {
	},
	[CHERIABI_SYS_thr_kill2] = {
	},
	[CHERIABI_SYS_shm_open] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_shm_unlink] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cpuset] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cpuset_setid] = {
	},
	[CHERIABI_SYS_cpuset_getid] = {
		.sam_ptrmask = 0x8
	},
	[CHERIABI_SYS_cpuset_getaffinity] = {
		.sam_ptrmask = 0x10
	},
	[CHERIABI_SYS_cpuset_setaffinity] = {
		.sam_ptrmask = 0x10
	},
	[CHERIABI_SYS_faccessat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_fchmodat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_fchownat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_fexecve] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_fstatat] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_futimesat] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_linkat] = {
		.sam_ptrmask = 0x2 | 0x8
	},
	[CHERIABI_SYS_mkdirat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_mkfifoat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_mknodat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_openat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_readlinkat] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_renameat] = {
		.sam_ptrmask = 0x2 | 0x8
	},
	[CHERIABI_SYS_symlinkat] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_unlinkat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_posix_openpt] = {
	},
	[CHERIABI_SYS_cheriabi_jail_get] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_jail_set] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_jail_remove] = {
	},
	[CHERIABI_SYS_closefrom] = {
	},
	[CHERIABI_SYS_cheriabi_semctl] = {
		.sam_ptrmask = 0x8
	},
	[CHERIABI_SYS_cheriabi_msgctl] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_shmctl] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_lpathconf] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS___cap_rights_get] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_cap_getmode] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_pdfork] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_pdkill] = {
	},
	[CHERIABI_SYS_pdgetpid] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_pselect] = {
		.sam_ptrmask = 0x2 | 0x4 | 0x8 | 0x10 | 0x20
	},
	[CHERIABI_SYS_getloginclass] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_setloginclass] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_rctl_get_racct] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_rctl_get_rules] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_rctl_get_limits] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_rctl_add_rule] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_rctl_remove_rule] = {
		.sam_ptrmask = 0x1 | 0x4
	},
	[CHERIABI_SYS_posix_fallocate] = {
	},
	[CHERIABI_SYS_posix_fadvise] = {
	},
	[CHERIABI_SYS_cheriabi_wait6] = {
		.sam_ptrmask = 0x4 | 0x10 | 0x20
	},
	[CHERIABI_SYS_cap_rights_limit] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_cap_ioctls_limit] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cheriabi_cap_ioctls_get] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_cap_fcntls_limit] = {
	},
	[CHERIABI_SYS_cap_fcntls_get] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_bindat] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_connectat] = {
		.sam_ptrmask = 0x4
	},
	[CHERIABI_SYS_chflagsat] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_accept4] = {
		.sam_ptrmask = 0x2 | 0x4
	},
	[CHERIABI_SYS_pipe2] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_cheriabi_aio_mlock] = {
		.sam_ptrmask = 0x1
	},
	[CHERIABI_SYS_procctl] = {
		.sam_ptrmask = 0x8
	},
	[CHERIABI_SYS_ppoll] = {
		.sam_ptrmask = 0x1 | 0x4 | 0x8
	},
	[CHERIABI_SYS_futimens] = {
		.sam_ptrmask = 0x2
	},
	[CHERIABI_SYS_utimensat] = {
		.sam_ptrmask = 0x2 | 0x4
	},
};
#endif /* !_CHERIABI_SYSARGMAP_H_ */
