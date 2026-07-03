/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2024-2026 Elastic NV */

#ifndef _COMPAT_H_
#define _COMPAT_H_

/* Linux specific */
#include <linux/types.h>

/* Sys */
#include <sys/types.h>

/* Standard */
#include <features.h>
#include <stdio.h>
#include <stdint.h>

/*
 * General compat
 */
/* uint64_t is historically defined as unsigned long on LONG architectures, not
 * unsigned long long, meaning we can't always use %llu for printing on 32 and
 * 64bit. We use __u64 which is saner.
 */
typedef __u64		u64;
typedef __s64		s64;
typedef __u32		u32;
typedef __s32		s32;
typedef __u16		u16;
typedef __s16		s16;
typedef __u8		u8;
typedef __s8		s8;
typedef uintptr_t	__uintptr_t;	/* for freebsd_tree.h */

#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif	/* __aligned */

#ifndef __weak
#define __weak		__attribute__((weak))
#endif	/* __weak */

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif	/* likely */

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif	/* unlikely */

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif	/* nitems */

/*
 * BSD compat
 */
#include "freebsd_queue.h"
#include "freebsd_tree.h"

#if !defined(SYSLIB) ||							\
	(defined(__GLIBC__) &&						\
	    (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 38)))
size_t		strlcat(char *, const char *, size_t);
size_t		strlcpy(char *, const char *, size_t);
#endif /* strlcpy, strlcat */
long long	strtonum(const char *, long long, long long, const char **);

/*
 * Misc
 */
void		sshbuf_dump_data(const void *, size_t, FILE *);

#ifndef HAVE_REALLOCARRAY
void		*reallocarray(void *, size_t, size_t);
#endif	/* HAVE_REALLOCARRAY */

/*
 * Base64, portable version of b64_*, so we don't have to link with libresolv
 */
int		qb64_ntop(u_char const *, size_t, char *, size_t);
int 		qb64_pton(char const *, u_char *, size_t);

#endif	/* _COMPAT_H */
