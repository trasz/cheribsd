/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181121,
 *   "target_type": "lib",
 *   "changes": [
 *     "integer_provenance"
 *   ]
 * }
 * CHERI CHANGES END
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)bcopy.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cheri_private.h"

/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
#if __has_feature(capabilities)
typedef	__intcap_t word;		/* "word" used for optimal copy speed */
#else
typedef	int word;		/* "word" used for optimal copy speed */
#endif

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

#if __has_feature(capabilities)
extern ssize_t	write(int, const void *, size_t);
#define write_to_stderr(str) write(2, (str), strlen(str))
extern int __sysctlbyname(const char *name, size_t namelen, void *oldp,
    size_t *oldlenp, const void *newp, size_t newlen);
#define ABORT_ON_TAG_LOSS_SYSCTL "security.cheri.abort_on_memcpy_tag_loss"
#define ABORT_ON_TAG_LOSS_ENVVAR "CHERI_ABORT_ON_TAG_STRIPPING_COPY"

static void
handle_untagged_copy(const void *__capability taggedcap, vaddr_t src_addr,
    vaddr_t dst_addr, size_t offset)
{
	char errmsg_buffer[1024];
	/* XXXAR: These functions do not exist yet... */
	snprintf(errmsg_buffer, sizeof(errmsg_buffer),
	    "%s: Attempting to copy a tagged capability (%#p) from 0x%jx to "
	    "underaligned destination 0x%jx. Use memmove_nocap()/memcpy_nocap()"
	    " if you intended to strip tags.\n", getprogname(),
#ifdef __CHERI_PURE_CAPABILITY__
	    taggedcap,
#else
	    /* Can't use capabilities in fprintf in hybrid mode */
	    (void *)(uintptr_t)(__cheri_addr vaddr_t)(taggedcap),
#endif
	    (uintmax_t)(src_addr + offset), (uintmax_t)(dst_addr + offset));
	write_to_stderr(errmsg_buffer);
	/* TODO: allow overriding the behaviour with a function pointer? */
	static uint32_t abort_on_tag_loss = -1;
	if (abort_on_tag_loss == -1) {
		const char *from_env = getenv(ABORT_ON_TAG_LOSS_ENVVAR);
		if (from_env != NULL) {
			/* Enabled unless empty or starts with zero. */
			if (*from_env == '\0' || *from_env == '0')
				abort_on_tag_loss = 0;
			else
				abort_on_tag_loss = 1;
		}
	}
	if (abort_on_tag_loss == -1) {
		/* If the env var is not set fall back to the global sysctl */
		size_t olen = sizeof(abort_on_tag_loss);
		if (__sysctlbyname(ABORT_ON_TAG_LOSS_SYSCTL,
			strlen(ABORT_ON_TAG_LOSS_SYSCTL), &abort_on_tag_loss,
			&olen, NULL, 0) == -1) {
			write_to_stderr("ERROR: could not determine whether "
			    "tag stripping memcpy should abort. Assuming it "
			    "shouldn't.\n");
			abort_on_tag_loss = 0;
		}
	}
	if (abort_on_tag_loss) {
		write_to_stderr("Note: accidental tag stripping is fatal, set "
				"the " ABORT_ON_TAG_LOSS_ENVVAR " environment "
				"variable or the " ABORT_ON_TAG_LOSS_SYSCTL
				" sysctl to 0 to disable this behaviour.\n");
		abort();
	}
}

/*
 * Check that we aren't attempting to copy a capabilities to a misaligned
 * destination (which would strip the tag bit instead of raising an exception).
 */
static __noinline __attribute((optnone)) void
check_no_tagged_capabilities_in_copy(
    const char *__CAP src, const char *__CAP dst, size_t len)
{
	static int error_logged = 0;

	if (len < sizeof(void *__capability)) {
		return; /* return early if copying less than a capability */
	}
	if (error_logged) {
		return; /* Only report one error */
	}
	const vaddr_t src_addr = (__cheri_addr vaddr_t)src;
	const vaddr_t to_first_cap =
	    __builtin_align_up(src_addr, sizeof(void *__capability)) - src_addr;
	const vaddr_t last_clc_offset = len - sizeof(void *__capability);
	for (vaddr_t offset = to_first_cap; offset <= last_clc_offset;
	     offset += sizeof(void *__capability)) {
		const void *__capability *__CAP aligned_src =
		    (const void *__capability *__CAP)(src + offset);
		if (__predict_true(!__builtin_cheri_tag_get(*aligned_src))) {
			continue; /* untagged values are fine */
		}

		if (error_logged)
			break;
		error_logged = 1;
		/* Got a tagged value, this is always an error! */
		handle_untagged_copy(
		    *aligned_src, src_addr, (__cheri_addr vaddr_t)dst, offset);
	}
}
#else
#define check_no_tagged_capabilities_in_copy(...) (void)0
#endif

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */
#if defined(MEMCOPY) || defined(MEMMOVE)
#include <string.h>

#ifdef IN_LIBSYSCALLS
__attribute__((weak, visibility("hidden")))
#endif
void * __CAP
#ifdef MEMCOPY
__CAPSUFFIX(memcpy)
#else
__CAPSUFFIX(memmove)
#endif
(void * __CAP dst0, const void * __CAP src0, size_t length)
#else
#include <strings.h>

void
bcopy(const void *src0, void *dst0, size_t length)
#endif
{
	char * __CAP dst = dst0;
	const char * __CAP src = src0;
	size_t t;

	if (length == 0 || dst == src)		/* nothing to do */
		goto done;

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if (dst < src) {
		/*
		 * Copy forward.
		 */
		t = (__cheri_addr size_t)src;	/* only need low bits */
		if ((t | (__cheri_addr size_t)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (__cheri_addr size_t)dst) & wmask || length < wsize) {
				t = length;
				check_no_tagged_capabilities_in_copy(src, dst, length);
			} else {
				t = wsize - (t & wmask);
			}
			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / wsize;
		TLOOP(*(word * __CAP)dst = *(const word * __CAP)src; src += wsize; dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		t = (__cheri_addr size_t)src;
		if ((t | (__cheri_addr size_t)dst) & wmask) {
			if ((t ^ (__cheri_addr size_t)dst) & wmask || length <= wsize) {
				check_no_tagged_capabilities_in_copy(
				    src - length, dst - length, length);
				t = length;
			} else {
				t &= wmask;
			}
			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
		TLOOP(src -= wsize; dst -= wsize; *(word * __CAP)dst = *(const word * __CAP)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
done:
#if defined(MEMCOPY) || defined(MEMMOVE)
	return (dst0);
#else
	return;
#endif
}
