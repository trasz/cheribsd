# FreeBSD system call object files.
# DO NOT EDIT-- this file is automatically generated.
# $FreeBSD$
MIASM =  \
	cheriabi_syscall.o \
	exit.o \
	fork.o \
	read.o \
	write.o \
	open.o \
	close.o \
	wait4.o \
	link.o \
	unlink.o \
	chdir.o \
	fchdir.o \
	chmod.o \
	chown.o \
	getpid.o \
	mount.o \
	unmount.o \
	setuid.o \
	getuid.o \
	geteuid.o \
	ptrace.o \
	cheriabi_recvmsg.o \
	cheriabi_sendmsg.o \
	recvfrom.o \
	accept.o \
	getpeername.o \
	getsockname.o \
	access.o \
	chflags.o \
	fchflags.o \
	sync.o \
	kill.o \
	getppid.o \
	dup.o \
	getegid.o \
	profil.o \
	ktrace.o \
	getgid.o \
	getlogin.o \
	setlogin.o \
	acct.o \
	cheriabi_sigaltstack.o \
	cheriabi_ioctl.o \
	reboot.o \
	revoke.o \
	symlink.o \
	readlink.o \
	cheriabi_execve.o \
	umask.o \
	chroot.o \
	msync.o \
	vfork.o \
	munmap.o \
	cheriabi_mprotect.o \
	cheriabi_madvise.o \
	mincore.o \
	getgroups.o \
	setgroups.o \
	getpgrp.o \
	setpgid.o \
	setitimer.o \
	swapon.o \
	getitimer.o \
	getdtablesize.o \
	dup2.o \
	fcntl.o \
	select.o \
	fsync.o \
	setpriority.o \
	socket.o \
	connect.o \
	getpriority.o \
	bind.o \
	setsockopt.o \
	listen.o \
	gettimeofday.o \
	getrusage.o \
	getsockopt.o \
	cheriabi_readv.o \
	cheriabi_writev.o \
	settimeofday.o \
	fchown.o \
	fchmod.o \
	setreuid.o \
	setregid.o \
	rename.o \
	flock.o \
	mkfifo.o \
	sendto.o \
	shutdown.o \
	socketpair.o \
	mkdir.o \
	rmdir.o \
	utimes.o \
	adjtime.o \
	setsid.o \
	quotactl.o \
	cheriabi_nlm_syscall.o \
	cheriabi_nfssvc.o \
	lgetfh.o \
	getfh.o \
	cheriabi_sysarch.o \
	rtprio.o \
	setfib.o \
	ntp_adjtime.o \
	setgid.o \
	setegid.o \
	seteuid.o \
	pathconf.o \
	fpathconf.o \
	getrlimit.o \
	setrlimit.o \
	__sysctl.o \
	mlock.o \
	munlock.o \
	undelete.o \
	futimes.o \
	getpgid.o \
	poll.o \
	semget.o \
	semop.o \
	msgget.o \
	msgsnd.o \
	msgrcv.o \
	shmat.o \
	shmdt.o \
	shmget.o \
	clock_gettime.o \
	clock_settime.o \
	clock_getres.o \
	cheriabi_ktimer_create.o \
	ktimer_delete.o \
	ktimer_settime.o \
	ktimer_gettime.o \
	ktimer_getoverrun.o \
	nanosleep.o \
	ffclock_getcounter.o \
	ffclock_setestimate.o \
	ffclock_getestimate.o \
	clock_nanosleep.o \
	clock_getcpuclockid2.o \
	ntp_gettime.o \
	minherit.o \
	rfork.o \
	issetugid.o \
	lchown.o \
	cheriabi_aio_read.o \
	cheriabi_aio_write.o \
	cheriabi_lio_listio.o \
	lchmod.o \
	lutimes.o \
	freebsd11_nstat.o \
	freebsd11_nfstat.o \
	freebsd11_nlstat.o \
	cheriabi_preadv.o \
	cheriabi_pwritev.o \
	fhopen.o \
	modnext.o \
	modstat.o \
	modfnext.o \
	modfind.o \
	kldload.o \
	kldunload.o \
	kldfind.o \
	kldnext.o \
	kldstat.o \
	kldfirstmod.o \
	getsid.o \
	setresuid.o \
	setresgid.o \
	cheriabi_aio_return.o \
	cheriabi_aio_suspend.o \
	cheriabi_aio_cancel.o \
	cheriabi_aio_error.o \
	mlockall.o \
	munlockall.o \
	__getcwd.o \
	sched_setparam.o \
	sched_getparam.o \
	sched_setscheduler.o \
	sched_getscheduler.o \
	sched_yield.o \
	sched_get_priority_max.o \
	sched_get_priority_min.o \
	sched_rr_get_interval.o \
	utrace.o \
	cheriabi_kldsym.o \
	cheriabi_jail.o \
	sigprocmask.o \
	sigsuspend.o \
	sigpending.o \
	cheriabi_sigtimedwait.o \
	cheriabi_sigwaitinfo.o \
	__acl_get_file.o \
	__acl_set_file.o \
	__acl_get_fd.o \
	__acl_set_fd.o \
	__acl_delete_file.o \
	__acl_delete_fd.o \
	__acl_aclcheck_file.o \
	__acl_aclcheck_fd.o \
	extattrctl.o \
	extattr_set_file.o \
	extattr_get_file.o \
	extattr_delete_file.o \
	cheriabi_aio_waitcomplete.o \
	getresuid.o \
	getresgid.o \
	kqueue.o \
	cheriabi_kevent.o \
	extattr_set_fd.o \
	extattr_get_fd.o \
	extattr_delete_fd.o \
	__setugid.o \
	eaccess.o \
	cheriabi_nmount.o \
	cheriabi___mac_get_proc.o \
	cheriabi___mac_set_proc.o \
	cheriabi___mac_get_fd.o \
	cheriabi___mac_get_file.o \
	cheriabi___mac_set_fd.o \
	cheriabi___mac_set_file.o \
	kenv.o \
	lchflags.o \
	uuidgen.o \
	cheriabi_sendfile.o \
	mac_syscall.o \
	cheriabi___mac_get_pid.o \
	cheriabi___mac_get_link.o \
	cheriabi___mac_set_link.o \
	extattr_set_link.o \
	extattr_get_link.o \
	extattr_delete_link.o \
	cheriabi___mac_execve.o \
	cheriabi_sigaction.o \
	cheriabi_sigreturn.o \
	cheriabi_getcontext.o \
	cheriabi_setcontext.o \
	cheriabi_swapcontext.o \
	swapoff.o \
	__acl_get_link.o \
	__acl_set_link.o \
	__acl_delete_link.o \
	__acl_aclcheck_link.o \
	sigwait.o \
	cheriabi_thr_create.o \
	thr_exit.o \
	thr_self.o \
	thr_kill.o \
	jail_attach.o \
	extattr_list_fd.o \
	extattr_list_file.o \
	extattr_list_link.o \
	ksem_timedwait.o \
	thr_suspend.o \
	thr_wake.o \
	kldunloadf.o \
	audit.o \
	auditon.o \
	getauid.o \
	setauid.o \
	getaudit.o \
	setaudit.o \
	getaudit_addr.o \
	setaudit_addr.o \
	auditctl.o \
	_umtx_op.o \
	cheriabi_thr_new.o \
	cheriabi_sigqueue.o \
	kmq_open.o \
	kmq_setattr.o \
	kmq_timedreceive.o \
	kmq_timedsend.o \
	cheriabi_kmq_notify.o \
	kmq_unlink.o \
	cheriabi_abort2.o \
	thr_set_name.o \
	cheriabi_aio_fsync.o \
	rtprio_thread.o \
	sctp_peeloff.o \
	sctp_generic_sendmsg.o \
	cheriabi_sctp_generic_sendmsg_iov.o \
	cheriabi_sctp_generic_recvmsg.o \
	pread.o \
	pwrite.o \
	cheriabi_mmap.o \
	lseek.o \
	truncate.o \
	ftruncate.o \
	thr_kill2.o \
	shm_open.o \
	shm_unlink.o \
	cpuset.o \
	cpuset_setid.o \
	cpuset_getid.o \
	cpuset_getaffinity.o \
	cpuset_setaffinity.o \
	faccessat.o \
	fchmodat.o \
	fchownat.o \
	cheriabi_fexecve.o \
	futimesat.o \
	linkat.o \
	mkdirat.o \
	mkfifoat.o \
	cheriabi_openat.o \
	readlinkat.o \
	renameat.o \
	symlinkat.o \
	unlinkat.o \
	posix_openpt.o \
	gssd_syscall.o \
	cheriabi_jail_get.o \
	cheriabi_jail_set.o \
	jail_remove.o \
	closefrom.o \
	cheriabi___semctl.o \
	cheriabi_msgctl.o \
	shmctl.o \
	lpathconf.o \
	__cap_rights_get.o \
	cap_enter.o \
	cap_getmode.o \
	pdfork.o \
	pdkill.o \
	pdgetpid.o \
	pselect.o \
	getloginclass.o \
	setloginclass.o \
	rctl_get_racct.o \
	rctl_get_rules.o \
	rctl_get_limits.o \
	rctl_add_rule.o \
	rctl_remove_rule.o \
	posix_fallocate.o \
	posix_fadvise.o \
	cheriabi_wait6.o \
	cap_rights_limit.o \
	cap_ioctls_limit.o \
	cap_ioctls_get.o \
	cap_fcntls_limit.o \
	cap_fcntls_get.o \
	bindat.o \
	connectat.o \
	chflagsat.o \
	accept4.o \
	pipe2.o \
	cheriabi_aio_mlock.o \
	cheriabi_procctl.o \
	ppoll.o \
	futimens.o \
	utimensat.o \
	numa_getaffinity.o \
	numa_setaffinity.o \
	fdatasync.o \
	fstat.o \
	fstatat.o \
	fhstat.o \
	getdirentries.o \
	statfs.o \
	fstatfs.o \
	getfsstat.o \
	fhstatfs.o \
	mknodat.o
