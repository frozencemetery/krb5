/*
 * Copyright 2007,2008,2009,2011,2012 Red Hat, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  Neither the name of Red Hat, Inc. nor the names of its contributors may be
 *  used to endorse or promote products derived from this software without
 *  specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * File-opening wrappers for creating correctly-labeled files.  So far, we can
 * assume that this is Linux-specific, so we make many simplifying assumptions.
 */

#include "../../include/autoconf.h"

#ifdef USE_SELINUX

#include <k5-label.h>
#include <k5-platform.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#ifdef HAVE_SELINUX_LABEL_H
#include <selinux/label.h>
#endif

/* #define DEBUG 1 */

/* Mutex used to serialize use of the process-global file creation context. */
k5_mutex_t labeled_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

/* Make sure we finish initializing that mutex before attempting to use it. */
k5_once_t labeled_once = K5_ONCE_INIT;
static void
label_mutex_init(void)
{
	k5_mutex_finish_init(&labeled_mutex);
}

#ifdef HAVE_SELINUX_LABEL_H
static struct selabel_handle *selabel_ctx;
static time_t selabel_last_changed;

MAKE_FINI_FUNCTION(cleanup_fscreatecon);

static void
cleanup_fscreatecon(void)
{
	if (selabel_ctx != NULL) {
		selabel_close(selabel_ctx);
		selabel_ctx = NULL;
	}
}
#endif

static security_context_t
push_fscreatecon(const char *pathname, mode_t mode)
{
	security_context_t previous, configuredsc, currentsc, derivedsc;
	context_t current, derived;
	const char *fullpath, *currentuser;

	previous = NULL;
	if (is_selinux_enabled()) {
		if (getfscreatecon(&previous) == 0) {
			char *genpath;
			genpath = NULL;
			if (pathname[0] != '/') {
				char *wd;
				size_t len;
				len = 0;
				wd = getcwd(NULL, len);
				if (wd == NULL) {
					if (previous != NULL) {
						freecon(previous);
					}
					cleanup_fscreatecon();
					return NULL;
				}
				len = strlen(wd) + 1 + strlen(pathname) + 1;
				genpath = malloc(len);
				if (genpath == NULL) {
					free(wd);
					if (previous != NULL) {
						freecon(previous);
					}
					cleanup_fscreatecon();
					return NULL;
				}
				sprintf(genpath, "%s/%s", wd, pathname);
				free(wd);
				fullpath = genpath;
			} else {
				fullpath = pathname;
			}
#ifdef DEBUG
			if (isatty(fileno(stderr))) {
				fprintf(stderr, "Looking up context for "
					"\"%s\"(%05o).\n", fullpath, mode);
			}
#endif
			configuredsc = NULL;
#ifdef HAVE_SELINUX_LABEL_H
			if ((selabel_ctx != NULL) ||
			    (selabel_last_changed == 0)) {
				const char *cpath;
				struct stat st;
				int i = -1;
				cpath = selinux_file_context_path();
				if ((cpath == NULL) ||
				    ((i = stat(cpath, &st)) != 0) ||
				    (st.st_mtime != selabel_last_changed)) {
					if (selabel_ctx != NULL) {
						selabel_close(selabel_ctx);
						selabel_ctx = NULL;
					}
					selabel_last_changed = i ?
							       time(NULL) :
							       st.st_mtime;
				}
			}
			if (selabel_ctx == NULL) {
				selabel_ctx = selabel_open(SELABEL_CTX_FILE,
							   NULL, 0);
			}
			if (selabel_ctx != NULL) {
				if (selabel_lookup(selabel_ctx, &configuredsc,
						   fullpath, mode) != 0) {
					free(genpath);
					if (previous != NULL) {
						freecon(previous);
					}
					cleanup_fscreatecon();
					return NULL;
				}
			}
#else
			if (matchpathcon(fullpath, mode, &configuredsc) != 0) {
				free(genpath);
				if (previous != NULL) {
					freecon(previous);
				}
				cleanup_fscreatecon();
				return NULL;
			}
#endif
			free(genpath);
			if (configuredsc == NULL) {
				if (previous != NULL) {
					freecon(previous);
				}
				cleanup_fscreatecon();
				return NULL;
			}
			currentsc = NULL;
			getcon(&currentsc);
			if (currentsc != NULL) {
				derived = context_new(configuredsc);
				if (derived != NULL) {
					current = context_new(currentsc);
					if (current != NULL) {
						currentuser = context_user_get(current);
						if (currentuser != NULL) {
							if (context_user_set(derived,
									     currentuser) == 0) {
								derivedsc = context_str(derived);
								if (derivedsc != NULL) {
									freecon(configuredsc);
									configuredsc = strdup(derivedsc);
								}
							}
						}
						context_free(current);
					}
					context_free(derived);
				}
				freecon(currentsc);
			}
#ifdef DEBUG
			if (isatty(fileno(stderr))) {
				fprintf(stderr, "Setting file creation context "
					"to \"%s\".\n", configuredsc);
			}
#endif
			if (setfscreatecon(configuredsc) != 0) {
				freecon(configuredsc);
				if (previous != NULL) {
					freecon(previous);
				}
				cleanup_fscreatecon();
				return NULL;
			}
			freecon(configuredsc);
#ifdef DEBUG
		} else {
			if (isatty(fileno(stderr))) {
				fprintf(stderr, "Unable to determine "
					"current context.\n");
			}
#endif
		}
	}
	return previous;
}

static void
pop_fscreatecon(security_context_t previous)
{
	if (is_selinux_enabled()) {
#ifdef DEBUG
		if (isatty(fileno(stderr))) {
			if (previous != NULL) {
				fprintf(stderr, "Resetting file creation "
					"context to \"%s\".\n", previous);
			} else {
				fprintf(stderr, "Resetting file creation "
					"context to default.\n");
			}
		}
#endif
		setfscreatecon(previous);
		if (previous != NULL) {
			freecon(previous);
		}
		cleanup_fscreatecon();
	}
}

void *
krb5int_push_fscreatecon_for(const char *pathname)
{
	struct stat st;
	void *retval;
	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		if (stat(pathname, &st) != 0) {
			st.st_mode = S_IRUSR | S_IWUSR;
		}
		retval = push_fscreatecon(pathname, st.st_mode);
		return retval ? retval : (void *) -1;
	} else {
		return NULL;
	}
}

void
krb5int_pop_fscreatecon(void *con)
{
	if (con != NULL) {
		pop_fscreatecon((con == (void *) -1) ? NULL : con);
		k5_mutex_unlock(&labeled_mutex);
	}
}

FILE *
krb5int_labeled_fopen(const char *path, const char *mode)
{
	FILE *fp;
	int errno_save;
	security_context_t ctx;

	if ((strcmp(mode, "r") == 0) ||
	    (strcmp(mode, "rb") == 0)) {
		return fopen(path, mode);
	}

	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		ctx = push_fscreatecon(path, 0);
		fp = fopen(path, mode);
		errno_save = errno;
		pop_fscreatecon(ctx);
		k5_mutex_unlock(&labeled_mutex);
		errno = errno_save;
	} else {
		fp = fopen(path, mode);
	}

	return fp;
}

int
krb5int_labeled_creat(const char *path, mode_t mode)
{
	int fd;
	int errno_save;
	security_context_t ctx;

	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		ctx = push_fscreatecon(path, 0);
		fd = creat(path, mode);
		errno_save = errno;
		pop_fscreatecon(ctx);
		k5_mutex_unlock(&labeled_mutex);
		errno = errno_save;
	} else {
		fd = creat(path, mode);
	}
	return fd;
}

int
krb5int_labeled_mknod(const char *path, mode_t mode, dev_t dev)
{
	int ret;
	int errno_save;
	security_context_t ctx;

	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		ctx = push_fscreatecon(path, mode);
		ret = mknod(path, mode, dev);
		errno_save = errno;
		pop_fscreatecon(ctx);
		k5_mutex_unlock(&labeled_mutex);
		errno = errno_save;
	} else {
		ret = mknod(path, mode, dev);
	}
	return ret;
}

int
krb5int_labeled_mkdir(const char *path, mode_t mode)
{
	int ret;
	int errno_save;
	security_context_t ctx;

	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		ctx = push_fscreatecon(path, S_IFDIR);
		ret = mkdir(path, mode);
		errno_save = errno;
		pop_fscreatecon(ctx);
		k5_mutex_unlock(&labeled_mutex);
		errno = errno_save;
	} else {
		ret = mkdir(path, mode);
	}
	return ret;
}

int
krb5int_labeled_open(const char *path, int flags, ...)
{
	int fd;
	int errno_save;
	security_context_t ctx;
	mode_t mode;
	va_list ap;

	if ((flags & O_CREAT) == 0) {
		return open(path, flags);
	}

	k5_once(&labeled_once, label_mutex_init);
	if (k5_mutex_lock(&labeled_mutex) == 0) {
		ctx = push_fscreatecon(path, 0);

		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		fd = open(path, flags, mode);
		va_end(ap);

		errno_save = errno;
		pop_fscreatecon(ctx);
		k5_mutex_unlock(&labeled_mutex);
		errno = errno_save;
	} else {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		fd = open(path, flags, mode);
		errno_save = errno;
		va_end(ap);
		errno = errno_save;
	}
	return fd;
}

#endif
