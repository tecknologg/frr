/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "zebra.h"

#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>

/* gettid() & co. */
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#ifdef linux
#include <sys/syscall.h>
#endif
#ifdef __FreeBSD__
#include <sys/thr.h>
#endif
#ifdef __NetBSD__
#include <lwp.h>
#endif
#ifdef __DragonFly__
#include <sys/lwp.h>
#endif
#ifdef __APPLE__
#include <mach/mach_traps.h>
#endif

#include "memory.h"
#include "atomlist.h"
#include "printfrr.h"
#include "frrcu.h"
#include "zlog.h"
#include "libfrr_trace.h"

DEFINE_MTYPE_STATIC(LIB, LOG_MESSAGE,  "log message")
DEFINE_MTYPE_STATIC(LIB, LOG_TLSBUF,   "log thread-local buffer")

DEFINE_HOOK(zlog_init, (const char *progname, const char *protoname,
			unsigned short instance, uid_t uid, gid_t gid),
		       (progname, protoname, instance, uid, gid))
DEFINE_KOOH(zlog_fini, (), ())
DEFINE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			   (prefix, prio_min))

static const struct zlog_kw_frame *zlog_kw_record(void);

char zlog_prefix[128];
size_t zlog_prefixsz;
int zlog_tmpdirfd = -1;

/* these are kept around because logging is initialized (and directories
 * & files created) before zprivs code switches to the FRR user;  therefore
 * we need to chown() things so we don't get permission errors later when
 * trying to delete things on shutdown
 */
static uid_t zlog_uid = -1;
static gid_t zlog_gid = -1;

DECLARE_ATOMLIST(zlog_targets, struct zlog_target, head);
static struct zlog_targets_head zlog_targets;

/* cf. zlog.h for additional comments on this struct.
 *
 * Note: you MUST NOT pass the format string + va_list to non-FRR format
 * string functions (e.g. vsyslog, sd_journal_printv, ...) since FRR uses an
 * extended prinf() with additional formats (%pI4 and the like).
 *
 * Also remember to use va_copy() on args.
 */

struct zlog_msg {
	struct timespec ts;
	int prio;

	const char *fmt;
	va_list args;
	const struct xref_logmsg *xref;

	char *stackbuf;
	size_t stackbufsz;
	char *text;
	size_t textlen;
	const struct zlog_kw_frame *kw_frame;

	/* This is always ISO8601 with sub-second precision 9 here, it's
	 * converted for callers as needed.  ts_dot points to the "."
	 * separating sub-seconds.  ts_zonetail is "Z" or "+00:00" for the
	 * local time offset.
	 *
	 * Valid if ZLOG_TS_ISO8601 is set.
	 * (0 if timestamp has not been formatted yet)
	 */
	uint32_t ts_flags;
	char ts_str[32], *ts_dot, ts_zonetail[8];
};

/* thread-local log message buffering
 *
 * This is strictly optional and set up by calling zlog_tls_buffer_init()
 * on a particular thread.
 *
 * If in use, this will create a temporary file in /var/tmp which is used as
 * memory-mapped MAP_SHARED log message buffer.  The idea there is that buffer
 * access doesn't require any syscalls, but in case of a crash the kernel
 * knows to sync the memory back to disk.  This way the user can still get the
 * last log messages if there were any left unwritten in the buffer.
 *
 * Sizing this dynamically isn't particularly useful, so here's an 8k buffer
 * with a message limit of 64 messages.  Message metadata (e.g. priority,
 * timestamp) aren't in the mmap region, so they're lost on crash, but we can
 * live with that.
 */

#if defined(HAVE_OPENAT) && defined(HAVE_UNLINKAT)
#define CAN_DO_TLS 1
#endif

#define TLS_LOG_BUF_SIZE	8192
#define TLS_LOG_MAXMSG		64

struct zlog_tls {
	char *mmbuf;
	size_t bufpos;

	size_t nmsgs;
	struct zlog_msg msgs[TLS_LOG_MAXMSG];
	struct zlog_msg *msgp[TLS_LOG_MAXMSG];
};

static inline void zlog_tls_free(void *arg);

/* proper ELF TLS is a bit faster than pthread_[gs]etspecific, so if it's
 * available we'll use it here
 */

#ifdef __OpenBSD__
static pthread_key_t zlog_tls_key;

static void zlog_tls_key_init(void) __attribute__((_CONSTRUCTOR(500)));
static void zlog_tls_key_init(void)
{
	pthread_key_create(&zlog_tls_key, zlog_tls_free);
}

static void zlog_tls_key_fini(void) __attribute__((_DESTRUCTOR(500)));
static void zlog_tls_key_fini(void)
{
	pthread_key_delete(zlog_tls_key);
}

static inline struct zlog_tls *zlog_tls_get(void)
{
	return pthread_getspecific(zlog_tls_key);
}

static inline void zlog_tls_set(struct zlog_tls *val)
{
	pthread_setspecific(zlog_tls_key, val);
}
#else
# ifndef thread_local
#  define thread_local __thread
# endif

static thread_local struct zlog_tls *zlog_tls_var
	__attribute__((tls_model("initial-exec")));

static inline struct zlog_tls *zlog_tls_get(void)
{
	return zlog_tls_var;
}

static inline void zlog_tls_set(struct zlog_tls *val)
{
	zlog_tls_var = val;
}
#endif

#ifdef CAN_DO_TLS
static long zlog_gettid(void)
{
	long rv = -1;
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	rv = pthread_getthreadid_np();
#elif defined(linux)
	rv = syscall(__NR_gettid);
#elif defined(__NetBSD__)
	rv = _lwp_self();
#elif defined(__FreeBSD__)
	thr_self(&rv);
#elif defined(__DragonFly__)
	rv = lwp_gettid();
#elif defined(__OpenBSD__)
	rv = getthrid();
#elif defined(__sun)
	rv = pthread_self();
#elif defined(__APPLE__)
	rv = mach_thread_self();
	mach_port_deallocate(mach_task_self(), rv);
#endif
	return rv;
}

void zlog_tls_buffer_init(void)
{
	struct zlog_tls *zlog_tls;
	char mmpath[MAXPATHLEN];
	int mmfd;
	size_t i;

	zlog_tls = zlog_tls_get();

	if (zlog_tls || zlog_tmpdirfd < 0)
		return;

	zlog_tls = XCALLOC(MTYPE_LOG_TLSBUF, sizeof(*zlog_tls));
	for (i = 0; i < array_size(zlog_tls->msgp); i++)
		zlog_tls->msgp[i] = &zlog_tls->msgs[i];

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%ld", zlog_gettid());

	mmfd = openat(zlog_tmpdirfd, mmpath,
		      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (mmfd < 0) {
		zlog_err("failed to open thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon;
	}
	fchown(mmfd, zlog_uid, zlog_gid);

#ifdef HAVE_POSIX_FALLOCATE
	if (posix_fallocate(mmfd, 0, TLS_LOG_BUF_SIZE) != 0)
	/* note next statement is under above if() */
#endif
	if (ftruncate(mmfd, TLS_LOG_BUF_SIZE) < 0) {
		zlog_err("failed to allocate thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon_unlink;
	}

	zlog_tls->mmbuf = mmap(NULL, TLS_LOG_BUF_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED, mmfd, 0);
	if (zlog_tls->mmbuf == MAP_FAILED) {
		zlog_err("failed to mmap thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon_unlink;
	}

	close(mmfd);
	zlog_tls_set(zlog_tls);
	return;

out_anon_unlink:
	unlink(mmpath);
	close(mmfd);
out_anon:

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
	zlog_tls->mmbuf = mmap(NULL, TLS_LOG_BUF_SIZE, PROT_READ | PROT_WRITE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (!zlog_tls->mmbuf) {
		zlog_err("failed to anonymous-mmap thread log buffer: %s",
			 strerror(errno));
		XFREE(MTYPE_LOG_TLSBUF, zlog_tls);
		zlog_tls_set(NULL);
		return;
	}

	zlog_tls_set(zlog_tls);
}

void zlog_tls_buffer_fini(void)
{
	char mmpath[MAXPATHLEN];

	zlog_tls_buffer_flush();

	zlog_tls_free(zlog_tls_get());
	zlog_tls_set(NULL);

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%ld", zlog_gettid());
	if (unlinkat(zlog_tmpdirfd, mmpath, 0))
		zlog_err("unlink logbuf: %s (%d)", strerror(errno), errno);
}

#else /* !CAN_DO_TLS */
void zlog_tls_buffer_init(void)
{
}

void zlog_tls_buffer_fini(void)
{
}
#endif

static inline void zlog_tls_free(void *arg)
{
	struct zlog_tls *zlog_tls = arg;

	if (!zlog_tls)
		return;

	munmap(zlog_tls->mmbuf, TLS_LOG_BUF_SIZE);
	XFREE(MTYPE_LOG_TLSBUF, zlog_tls);
}

void zlog_tls_buffer_flush(void)
{
	struct zlog_target *zt;
	struct zlog_tls *zlog_tls = zlog_tls_get();

	if (!zlog_tls)
		return;
	if (!zlog_tls->nmsgs)
		return;

	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (!zt->logfn)
			continue;

		zt->logfn(zt, zlog_tls->msgp, zlog_tls->nmsgs);
	}
	rcu_read_unlock();

	zlog_tls->bufpos = 0;
	zlog_tls->nmsgs = 0;
}


static void vzlog_notls(const struct xref_logmsg *xref, int prio,
			const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg stackmsg = {
		.prio = prio & LOG_PRIMASK,
		.fmt = fmt,
		.xref = xref,
		.kw_frame = zlog_kw_record(),
	}, *msg = &stackmsg;
	char stackbuf[512];

	clock_gettime(CLOCK_REALTIME, &msg->ts);
	va_copy(msg->args, ap);
	msg->stackbuf = stackbuf;
	msg->stackbufsz = sizeof(stackbuf);

	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (prio > zt->prio_min)
			continue;
		if (!zt->logfn)
			continue;

		zt->logfn(zt, &msg, 1);
	}
	rcu_read_unlock();

	va_end(msg->args);
	if (msg->text && msg->text != stackbuf)
		XFREE(MTYPE_LOG_MESSAGE, msg->text);
}

static void vzlog_tls(struct zlog_tls *zlog_tls, const struct xref_logmsg *xref,
		      int prio, const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg *msg;
	char *buf;
	bool ignoremsg = true;
	bool immediate = false;

	/* avoid further processing cost if no target wants this message */
	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (prio > zt->prio_min)
			continue;
		ignoremsg = false;
		break;
	}
	rcu_read_unlock();

	if (ignoremsg)
		return;

	msg = &zlog_tls->msgs[zlog_tls->nmsgs];
	zlog_tls->nmsgs++;
	if (zlog_tls->nmsgs == array_size(zlog_tls->msgs))
		immediate = true;

	memset(msg, 0, sizeof(*msg));
	clock_gettime(CLOCK_REALTIME, &msg->ts);
	va_copy(msg->args, ap);
	msg->stackbuf = buf = zlog_tls->mmbuf + zlog_tls->bufpos;
	msg->stackbufsz = TLS_LOG_BUF_SIZE - zlog_tls->bufpos - 1;
	msg->fmt = fmt;
	msg->prio = prio & LOG_PRIMASK;
	msg->xref = xref;
	msg->kw_frame = zlog_kw_record();
	if (msg->prio < LOG_INFO)
		immediate = true;

	if (!immediate) {
		/* messages written later need to take the formatting cost
		 * immediately since we can't hold a reference on varargs
		 */
		zlog_msg_text(msg, NULL);

		if (msg->text != buf)
			/* zlog_msg_text called malloc() on us :( */
			immediate = true;
		else {
			zlog_tls->bufpos += msg->textlen + 1;
			/* write a second \0 to mark current end position
			 * (in case of crash this signals end of unwritten log
			 * messages in mmap'd logbuf file)
			 */
			zlog_tls->mmbuf[zlog_tls->bufpos] = '\0';

			/* avoid malloc() for next message */
			if (TLS_LOG_BUF_SIZE - zlog_tls->bufpos < 256)
				immediate = true;
		}
	}

	if (immediate)
		zlog_tls_buffer_flush();

	va_end(msg->args);
	if (msg->text && msg->text != buf)
		XFREE(MTYPE_LOG_MESSAGE, msg->text);
}

void vzlogx(const struct xref_logmsg *xref, int prio,
	    const char *fmt, va_list ap)
{
	struct zlog_tls *zlog_tls = zlog_tls_get();

#ifdef HAVE_LTTNG
	va_list copy;
	va_copy(copy, ap);
	char *msg = vasprintfrr(MTYPE_LOG_MESSAGE, fmt, copy);

	switch (prio) {
	case LOG_ERR:
		frrtracelog(TRACE_ERR, msg);
		break;
	case LOG_WARNING:
		frrtracelog(TRACE_WARNING, msg);
		break;
	case LOG_DEBUG:
		frrtracelog(TRACE_DEBUG, msg);
		break;
	case LOG_NOTICE:
		frrtracelog(TRACE_DEBUG, msg);
		break;
	case LOG_INFO:
	default:
		frrtracelog(TRACE_INFO, msg);
		break;
	}

	va_end(copy);
	XFREE(MTYPE_LOG_MESSAGE, msg);
#endif

	if (zlog_tls)
		vzlog_tls(zlog_tls, xref, prio, fmt, ap);
	else
		vzlog_notls(xref, prio, fmt, ap);
}

void vzlogdbg(const struct xref_logdebug *xref, int prio, const char *fmt, va_list ap)
{
	struct zlog_tls *zlog_tls = zlog_tls_get();

	if (!xref->debugflag->enable)
		return;

	if (zlog_tls)
		vzlog_tls(zlog_tls, &xref->logmsg, prio, fmt, ap);
	else
		vzlog_notls(&xref->logmsg, prio, fmt, ap);
}

void zlog_sigsafe(const char *text, size_t len)
{
	struct zlog_target *zt;
	const char *end = text + len, *nlpos;

	while (text < end) {
		nlpos = memchr(text, '\n', end - text);
		if (!nlpos)
			nlpos = end;

		frr_each (zlog_targets, &zlog_targets, zt) {
			if (LOG_CRIT > zt->prio_min)
				continue;
			if (!zt->logfn_sigsafe)
				continue;

			zt->logfn_sigsafe(zt, text, nlpos - text);
		}

		if (nlpos == end)
			break;
		text = nlpos + 1;
	}
}


int zlog_msg_prio(struct zlog_msg *msg)
{
	return msg->prio;
}

const struct xref_logmsg *zlog_msg_xref(struct zlog_msg *msg)
{
	return msg->xref;
}

const struct zlog_kw_frame *zlog_msg_frame(struct zlog_msg *msg)
{
	return msg->kw_frame;
}

const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen)
{
	if (!msg->text) {
		va_list args;

		va_copy(args, msg->args);
		msg->text = vasnprintfrr(MTYPE_LOG_MESSAGE, msg->stackbuf,
					 msg->stackbufsz, msg->fmt, args);
		msg->textlen = strlen(msg->text);
		va_end(args);
	}
	if (textlen)
		*textlen = msg->textlen;
	return msg->text;
}

#define ZLOG_TS_FORMAT		(ZLOG_TS_ISO8601 | ZLOG_TS_LEGACY)
#define ZLOG_TS_FLAGS		~ZLOG_TS_PREC

size_t zlog_msg_ts(struct zlog_msg *msg, char *out, size_t outsz,
		   uint32_t flags)
{
	size_t len1;

	if (!(flags & ZLOG_TS_FORMAT))
		return 0;

	if (!(msg->ts_flags & ZLOG_TS_FORMAT) ||
	    ((msg->ts_flags ^ flags) & ZLOG_TS_UTC)) {
		struct tm tm;

		if (flags & ZLOG_TS_UTC)
			gmtime_r(&msg->ts.tv_sec, &tm);
		else
			localtime_r(&msg->ts.tv_sec, &tm);

		strftime(msg->ts_str, sizeof(msg->ts_str),
			 "%Y-%m-%dT%H:%M:%S", &tm);

		if (flags & ZLOG_TS_UTC) {
			msg->ts_zonetail[0] = 'Z';
			msg->ts_zonetail[1] = '\0';
		} else
			snprintfrr(msg->ts_zonetail, sizeof(msg->ts_zonetail),
				   "%+03d:%02d",
				   (int)(tm.tm_gmtoff / 3600),
				   (int)(labs(tm.tm_gmtoff) / 60) % 60);

		msg->ts_dot = msg->ts_str + strlen(msg->ts_str);
		snprintfrr(msg->ts_dot,
			   msg->ts_str + sizeof(msg->ts_str) - msg->ts_dot,
			   ".%09lu", (unsigned long)msg->ts.tv_nsec);

		msg->ts_flags = ZLOG_TS_ISO8601 | (flags & ZLOG_TS_UTC);
	}

	len1 = flags & ZLOG_TS_PREC;
	len1 = (msg->ts_dot - msg->ts_str) + (len1 ? len1 + 1 : 0);

	if (len1 > strlen(msg->ts_str))
		len1 = strlen(msg->ts_str);

	if (flags & ZLOG_TS_LEGACY) {
		if (len1 + 1 > outsz)
			return 0;

		/* just swap out the formatting, faster than redoing it */
		for (char *p = msg->ts_str; p < msg->ts_str + len1; p++) {
			switch (*p) {
			case '-':
				*out++ = '/';
				break;
			case 'T':
				*out++ = ' ';
				break;
			default:
				*out++ = *p;
			}
		}
		*out = '\0';
		return len1;
	} else {
		size_t len2 = strlen(msg->ts_zonetail);

		if (len1 + len2 + 1 > outsz)
			return 0;
		memcpy(out, msg->ts_str, len1);
		memcpy(out + len1, msg->ts_zonetail, len2);
		out[len1 + len2] = '\0';
		return len1 + len2;
	}
}

void zlog_msg_tsraw(struct zlog_msg *msg, struct timespec *ts)
{
	memcpy(ts, &msg->ts, sizeof(*ts));
}

/* setup functions */

struct zlog_target *zlog_target_clone(struct memtype *mt,
				      struct zlog_target *oldzt, size_t size)
{
	struct zlog_target *newzt;

	newzt = XCALLOC(mt, size);
	if (oldzt) {
		newzt->prio_min = oldzt->prio_min;
		newzt->logfn = oldzt->logfn;
		newzt->logfn_sigsafe = oldzt->logfn_sigsafe;
	}

	return newzt;
}

struct zlog_target *zlog_target_replace(struct zlog_target *oldzt,
					struct zlog_target *newzt)
{
	if (newzt)
		zlog_targets_add_tail(&zlog_targets, newzt);
	if (oldzt)
		zlog_targets_del(&zlog_targets, oldzt);
	return oldzt;
}


/* common init */

#define TMPBASEDIR "/var/tmp/frr"

static char zlog_tmpdir[MAXPATHLEN];

void zlog_aux_init(const char *prefix, int prio_min)
{
	if (prefix)
		strlcpy(zlog_prefix, prefix, sizeof(zlog_prefix));

	hook_call(zlog_aux_init, prefix, prio_min);
}

void zlog_init(const char *progname, const char *protoname,
	       unsigned short instance, uid_t uid, gid_t gid)
{
	zlog_uid = uid;
	zlog_gid = gid;

	if (instance) {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir),
			   "/var/tmp/frr/%s-%d.%ld",
			   progname, instance, (long)getpid());

		zlog_prefixsz = snprintfrr(zlog_prefix, sizeof(zlog_prefix),
					   "%s[%d]: ", protoname, instance);
	} else {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir),
			   "/var/tmp/frr/%s.%ld",
			   progname, (long)getpid());

		zlog_prefixsz = snprintfrr(zlog_prefix, sizeof(zlog_prefix),
					   "%s: ", protoname);
	}

	if (mkdir(TMPBASEDIR, 0700) != 0) {
		if (errno != EEXIST) {
			zlog_err("failed to mkdir \"%s\": %s",
				 TMPBASEDIR, strerror(errno));
			goto out_warn;
		}
	}
	chown(TMPBASEDIR, zlog_uid, zlog_gid);

	if (mkdir(zlog_tmpdir, 0700) != 0) {
		zlog_err("failed to mkdir \"%s\": %s",
			 zlog_tmpdir, strerror(errno));
		goto out_warn;
	}

#ifdef O_PATH
	zlog_tmpdirfd = open(zlog_tmpdir,
			     O_PATH | O_RDONLY | O_CLOEXEC);
#else
	zlog_tmpdirfd = open(zlog_tmpdir,
			     O_DIRECTORY | O_RDONLY | O_CLOEXEC);
#endif
	if (zlog_tmpdirfd < 0) {
		zlog_err("failed to open \"%s\": %s",
			 zlog_tmpdir, strerror(errno));
		goto out_warn;
	}

#ifdef AT_EMPTY_PATH
	fchownat(zlog_tmpdirfd, "", zlog_uid, zlog_gid, AT_EMPTY_PATH);
#else
	chown(zlog_tmpdir, zlog_uid, zlog_gid);
#endif

	hook_call(zlog_init, progname, protoname, instance, uid, gid);
	return;

out_warn:
	zlog_err("crashlog and per-thread log buffering unavailable!");
	hook_call(zlog_init, progname, protoname, instance, uid, gid);
}

void zlog_fini(void)
{
	hook_call(zlog_fini);

	if (zlog_tmpdirfd >= 0) {
		close(zlog_tmpdirfd);
		zlog_tmpdirfd = -1;

		if (rmdir(zlog_tmpdir))
			zlog_err("failed to rmdir \"%s\": %s",
				 zlog_tmpdir, strerror(errno));
	}
}

DEFINE_MTYPE_STATIC(LIB, KW_SPACE, "Log key-value accumulation buffer")
DEFINE_MTYPE_STATIC(LIB, KW_HEAP,  "Log key-value reference")

struct zlog_kw zlkw_INVALID[1] = { { NULL } };

struct zlog_kw_state {
	struct zlog_kw_frame *current;

	size_t kw_space_size;
	char *kw_space;
};

static thread_local struct zlog_kw_state zlog_kw_state;

static const struct zlog_kw_frame *zlog_kw_record(void)
{
	return zlog_kw_state.current;
}

struct zlog_kw_state *_zlog_kw_frame_init(struct zlog_kw_frame *fvar,
					  unsigned size)
{
	struct zlog_kw_state *state = &zlog_kw_state;
	struct zlog_kw_frame *up = state->current;

	fvar->n_alloc = size;

	fvar->up = up;
	fvar->heapcopy = NULL;

	state->current = fvar;
	zlog_kw_revert(state);
	return state;
}

void _zlog_kw_frame_fini(struct zlog_kw_state **statep)
{
	if (*statep) {
		struct zlog_kw_state *state = *statep;

		zlog_tls_buffer_flush();

		zlog_kw_unref(&state->current->heapcopy);
		state->current = state->current->up;
		*statep = NULL;
	}
}

void _zlog_kw_push(struct zlog_kw_state *state, const struct xref *xref,
		   struct zlog_kw *key, const char *fmt, ...)
{
	struct zlog_kw_frame *frame = state->current;
	struct fbuf fb;
	size_t offset;
	ssize_t len;
	va_list ap;
	size_t i;

	assert(frame);

	if (frame->n_used)
		offset = frame->keywords[frame->n_used - 1].end;
	else
		offset = 0;

	assert(state->kw_space_size >= offset);

	fb.buf = state->kw_space;
	fb.pos = fb.buf + offset;
	fb.len = state->kw_space_size;

	va_start(ap, fmt);
	len = vbprintfrr(&fb, fmt, ap);
	va_end(ap);

	if ((size_t)(len + 1) > state->kw_space_size - offset) {
		size_t newsize = offset + len + 256;

		newsize = (newsize + 4095) & ~4095ULL;
		state->kw_space = XREALLOC(MTYPE_KW_SPACE, state->kw_space,
					   newsize);
		state->kw_space_size = newsize;

		fb.buf = state->kw_space;
		fb.pos = fb.buf + offset;
		fb.len = state->kw_space_size;

		va_start(ap, fmt);
		len = vbprintfrr(&fb, fmt, ap);
		va_end(ap);
	}
	
	state->kw_space[offset + len] = '\0';

	for (i = 0; i < frame->n_used; i++) {
		const char *oldval;

		if (frame->keywords[i].key != key)
			continue;

		oldval = state->kw_space + frame->keywords[i].start;
		if (strcmp(oldval, state->kw_space + offset))
			break;

		if (frame->keywords[frame->n_used].origin == xref)
			return;

		zlog_tls_buffer_flush();
		zlog_kw_unref(&frame->heapcopy);
		frame->keywords[frame->n_used].origin = xref;
		return;
	}

	zlog_tls_buffer_flush();

	if (i < frame->n_used)
		frame->keywords[i].key = zlkw_INVALID;

	assert(frame->n_used < frame->n_alloc);

	frame->keywords[frame->n_used].key = key;
	frame->keywords[frame->n_used].origin = xref;
	frame->keywords[frame->n_used].start = offset;
	frame->keywords[frame->n_used].end = offset + len + 1;
	zlog_kw_unref(&frame->heapcopy);
	frame->n_used++;
}

void zlog_kw_revert(struct zlog_kw_state *state)
{
	struct zlog_kw_frame *frame = state->current;
	struct zlog_kw_frame *up = frame->up;
	struct zlog_kw_heap *heapcopy = NULL;

	assert(frame);
	zlog_tls_buffer_flush();

	frame->n_used = up ? up->n_used : 0;

	if (up && up->heapcopy)
		heapcopy = zlog_kw_ref(up->heapcopy);
	zlog_kw_unref(&frame->heapcopy);
	frame->heapcopy = heapcopy;

	assert(frame->n_used <= frame->n_alloc);

	memcpy(frame->keywords, up->keywords,
	       sizeof(frame->keywords[0]) * frame->n_used);
	memset(frame->keywords + frame->n_used, 0,
	       sizeof(frame->keywords[0]) * (frame->n_alloc - frame->n_used));
}

void zlog_kw_clear(struct zlog_kw_state *state)
{
	struct zlog_kw_frame *frame = state->current;

	assert(frame);
	zlog_tls_buffer_flush();

	if (frame->n_used == 0)
		return;
	if (frame->n_used == 1 && frame->keywords[0].key == zlkw_INVALID)
		return;

	frame->keywords[0].start = 0;
	frame->keywords[0].end = frame->keywords[frame->n_used - 1].end;
	frame->keywords[0].key = zlkw_INVALID;

	memset(frame->keywords + 1, 0,
	       sizeof(frame->keywords[0]) * (frame->n_alloc - 1));

	zlog_kw_unref(&frame->heapcopy);
	frame->n_used = 1;
}

unsigned zlog_kw_count(void)
{
	struct zlog_kw_state *state = &zlog_kw_state;

	return state->current ? state->current->n_used : 0;
}

const char *zlog_kw_get(struct zlog_kw *kw)
{
	struct zlog_kw_state *state = &zlog_kw_state;
	struct zlog_kw_frame *frame = state->current;
	size_t i;

	if (!frame)
		return NULL;

	for (i = 0; i < frame->n_used; i++)
		if (frame->keywords[i].key == kw)
			return state->kw_space + frame->keywords[i].start;

	return NULL;
}

void zlog_kw_dump(void)
{
	struct zlog_kw_state *state = &zlog_kw_state;
	struct zlog_kw_frame *frame = state->current;
	size_t i;

	if (!frame) {
		zlog_debug("keyword stack is empty");
		return;
	}

	zlog_debug("%u keywords on stack", frame->n_used);
	for (i = 0; i < frame->n_used; i++) {
		if (frame->keywords[i].key == zlkw_INVALID)
			zlog_debug("  (void key)");
		else
			zlog_debug("  %s=\"%s\"", frame->keywords[i].key->name,
				   state->kw_space + frame->keywords[i].start);
	}
}

struct zlog_kw_heap *zlog_kw_save(void)
{
	struct zlog_kw_state *state = &zlog_kw_state;
	struct zlog_kw_frame *frame = state->current;

	if (!frame || frame->n_used == 0)
		return NULL;
	if (frame->heapcopy)
		return zlog_kw_ref(frame->heapcopy);

	size_t i, kw_need = 0;
	size_t char_need = 0;
	struct zlog_kw_val *val;

	for (i = 0; i < frame->n_used; i++) {
		val = &frame->keywords[i];
		if (val->key == zlkw_INVALID)
			continue;

		kw_need++;
		char_need += val->end - val->start;
	}

	struct zlog_kw_heap *alloc;
	char *char_base;
	unsigned offset;

	alloc = XMALLOC(MTYPE_KW_HEAP, sizeof(*alloc)
			+ kw_need * sizeof(alloc->keywords[0]) + char_need);

	/* one for the return value, one for frame->heapcopy */
	alloc->refcount = 2;
	alloc->n_keywords = kw_need;
	val = &alloc->keywords[0];
	char_base = (char *)&alloc->keywords[alloc->n_keywords];
	offset = 0;

	for (i = 0; i < frame->n_used; i++) {
		const char *src;
		size_t len;

		if (frame->keywords[i].key == zlkw_INVALID)
			continue;

		val->key = frame->keywords[i].key;
		val->origin = frame->keywords[i].origin;
		val->start = offset;

		src = state->kw_space + frame->keywords[i].start;
		len = frame->keywords[i].end - frame->keywords[i].start;
		memcpy(char_base + offset, src, len);
		offset += len;

		val->end = offset;
		val++;
	}

	assert(val == &alloc->keywords[alloc->n_keywords]);

	frame->heapcopy = alloc;
	return alloc;
}

void zlog_kw_apply(struct zlog_kw_state *state, struct zlog_kw_heap *heapkw)
{
	struct zlog_kw_frame *frame = state->current;
	unsigned val_start, total_len;
	char *char_base;
	size_t i, j;

	assert(frame);

	zlog_kw_clear(state);

	if (!heapkw)
		return;
	if (!heapkw->n_keywords)
		return;

	if (frame->n_used)
		val_start = frame->keywords[frame->n_used - 1].end;
	else
		val_start = 0;

	total_len = heapkw->keywords[heapkw->n_keywords - 1].end;

	if (state->kw_space_size - val_start < total_len) {
		size_t newsize = state->kw_space_size + total_len + 256;

		newsize = (newsize + 4095) & ~4095ULL;
		state->kw_space = XREALLOC(MTYPE_KW_SPACE, state->kw_space,
					   newsize);
		state->kw_space_size = newsize;
	}

	char_base = (char *)&heapkw->keywords[heapkw->n_keywords];
	memcpy(state->kw_space + val_start, char_base, total_len);

	j = frame->n_used;

	for (i = 0; i < heapkw->n_keywords; i++) {
		if (j == frame->n_alloc) {
			zlog_err("out of space while loading keywords");
			return;
		}

		frame->keywords[j] = heapkw->keywords[i];
		frame->keywords[j].start += val_start;
		frame->keywords[j].end += val_start;
		j++;
	}

	frame->n_used = j;
	frame->heapcopy = zlog_kw_ref(heapkw);
}

struct zlog_kw_heap *zlog_kw_ref(struct zlog_kw_heap *heapkw)
{
	assert(heapkw);
	assert(heapkw->refcount);

	heapkw->refcount++;
	return heapkw;
}

void zlog_kw_unref(struct zlog_kw_heap **heapkw)
{
	if (!heapkw || !*heapkw)
		return;

	(*heapkw)->refcount--;
	if ((*heapkw)->refcount == 0)
		XFREE(MTYPE_KW_HEAP, *heapkw);
	*heapkw = NULL;
}

size_t zlog_kw_frame_count(const struct zlog_kw_frame *frame)
{
	size_t i;

	if (!frame)
		return 0;
	for (i = 0; i < frame->n_used; i++)
		if (frame->keywords[i].key != zlkw_INVALID)
			i++;
	return i;
}

const struct zlog_kw_val *zlog_kw_frame_vals_next(
	const struct zlog_kw_frame *frame, const struct zlog_kw_val *prev)
{
	if (!frame)
		return NULL;
	do {
		prev++;
		if (prev >= &frame->keywords[frame->n_used])
			return NULL;
	} while (prev->key == zlkw_INVALID);

	return prev;
}

const struct zlog_kw_val *zlog_kw_frame_vals_first(
	const struct zlog_kw_frame *frame)
{
	return zlog_kw_frame_vals_next(frame, &frame->keywords[0] - 1);
}

const char *zlog_kw_frame_val_str(const struct zlog_kw_val *val)
{
	struct zlog_kw_state *state = &zlog_kw_state;

	return state->kw_space + val->start;
}
