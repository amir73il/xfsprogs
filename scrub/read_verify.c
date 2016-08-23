/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "libxfs.h"
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#include "disk.h"
#include "scrub.h"
#include "../repair/threads.h"
#include "read_verify.h"

/* How many bytes have we verified? */
static pthread_mutex_t		verified_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long	verified_bytes;

/* Tolerate 64k holes in adjacent read verify requests. */
#define IO_BATCH_LOCALITY	(65536)

/* Create a thread pool to run read verifiers. */
bool
read_verify_pool_init(
	struct read_verify_pool		*rvp,
	struct scrub_ctx		*ctx,
	void				*readbuf,
	size_t				readbufsz,
	size_t				min_io_sz,
	read_verify_ioend_fn_t		ioend_fn,
	unsigned int			nproc)
{
	rvp->rvp_readbuf = readbuf;
	rvp->rvp_readbufsz = readbufsz;
	rvp->rvp_ctx = ctx;
	rvp->rvp_min_io_size = min_io_sz;
	rvp->ioend_fn = ioend_fn;
	rvp->rvp_nproc = nproc;
	create_work_queue(&rvp->rvp_wq, (struct xfs_mount *)rvp, nproc);
	return true;
}

/* How many bytes has this process verified? */
unsigned long long
read_verify_bytes(void)
{
	return verified_bytes;
}

/* Finish up any read verification work and tear it down. */
void
read_verify_pool_destroy(
	struct read_verify_pool		*rvp)
{
	destroy_work_queue(&rvp->rvp_wq);
	memset(&rvp->rvp_wq, 0, sizeof(struct work_queue));
}

/*
 * Issue a read-verify IO in big batches.
 */
static void
read_verify(
	struct work_queue		*wq,
	xfs_agnumber_t			agno,
	void				*arg)
{
	struct read_verify		*rv = arg;
	struct read_verify_pool		*rvp;
	unsigned long long		verified = 0;
	ssize_t				sz;
	ssize_t				len;

	rvp = (struct read_verify_pool *)wq->mp;
	while (rv->io_length > 0) {
		len = min(rv->io_length, rvp->rvp_readbufsz);
		dbg_printf("diskverify %d %"PRIu64" %zu\n", rv->io_disk->d_fd,
				rv->io_start, len);
		sz = disk_read_verify(rv->io_disk, rvp->rvp_readbuf,
				rv->io_start, len);
		if (sz < 0) {
			dbg_printf("IOERR %d %"PRIu64" %zu\n",
					rv->io_disk->d_fd,
					rv->io_start, len);
			rvp->ioend_fn(rvp, rv->io_disk, rv->io_start,
					rvp->rvp_min_io_size,
					errno, rv->io_end_arg);
			len = rvp->rvp_min_io_size;
		}

		verified += len;
		rv->io_start += len;
		rv->io_length -= len;
	}

	free(rv);
	pthread_mutex_lock(&verified_lock);
	verified_bytes += verified;
	pthread_mutex_unlock(&verified_lock);
}

/* Queue a read verify request. */
static void
read_verify_queue(
	struct read_verify_pool		*rvp,
	struct read_verify		*rv)
{
	struct read_verify		*tmp;

	dbg_printf("verify fd %d start %"PRIu64" len %"PRIu64"\n",
			rv->io_disk->d_fd, rv->io_start, rv->io_length);

	tmp = malloc(sizeof(struct read_verify));
	if (!tmp) {
		rvp->ioend_fn(rvp, rv->io_disk, rv->io_start, rv->io_length,
				errno, rv->io_end_arg);
		return;
	}
	*tmp = *rv;

	queue_work(&rvp->rvp_wq, read_verify, 0, tmp);
}

/*
 * Issue an IO request.  We'll batch subsequent requests if they're
 * within 64k of each other
 */
void
read_verify_schedule(
	struct read_verify_pool		*rvp,
	struct read_verify		*rv,
	struct disk			*disk,
	uint64_t			start,
	uint64_t			length,
	void				*end_arg)
{
	uint64_t			ve_end;
	uint64_t			io_end;

	assert(rvp->rvp_readbuf);
	ve_end = start + length;
	io_end = rv->io_start + rv->io_length;

	/*
	 * If we have a stashed IO, we haven't changed fds, the error
	 * reporting is the same, and the two extents are close,
	 * we can combine them.
	 */
	if (rv->io_length > 0 && disk == rv->io_disk &&
	    end_arg == rv->io_end_arg &&
	    ((start >= rv->io_start && start <= io_end + IO_BATCH_LOCALITY) ||
	     (rv->io_start >= start &&
	      rv->io_start <= ve_end + IO_BATCH_LOCALITY))) {
		rv->io_start = min(rv->io_start, start);
		rv->io_length = max(ve_end, io_end) - rv->io_start;
	} else  {
		/* Otherwise, issue the stashed IO (if there is one) */
		if (rv->io_length > 0)
			read_verify_queue(rvp, rv);

		/* Stash the new IO. */
		rv->io_disk = disk;
		rv->io_start = start;
		rv->io_length = length;
		rv->io_end_arg = end_arg;
	}
}

/* Force any stashed IOs into the verifier. */
void
read_verify_force(
	struct read_verify_pool		*rvp,
	struct read_verify		*rv)
{
	assert(rvp->rvp_readbuf);
	if (rv->io_length == 0)
		return;

	read_verify_queue(rvp, rv);
	rv->io_length = 0;
}

/* Read all the data in a file. */
bool
read_verify_file(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	struct stat64		*sb)
{
	off_t			data_end = 0;
	off_t			data_start;
	off_t			start;
	ssize_t			sz;
	size_t			count;
	unsigned long long	verified = 0;
	bool			reports_holes = true;
	bool			direct_io = false;
	bool			moveon = true;
	int			flags;
	int			error;

	/*
	 * Try to force the kernel to read file data from disk.  First
	 * we try to set O_DIRECT.  If that fails, try to purge the page
	 * cache.
	 */
	flags = fcntl(fd, F_GETFL);
	error = fcntl(fd, F_SETFL, flags | O_DIRECT);
	if (error)
		posix_fadvise(fd, 0, sb->st_size, POSIX_FADV_DONTNEED);
	else
		direct_io = true;

	/* See if SEEK_DATA/SEEK_HOLE work... */
	data_start = lseek(fd, data_end, SEEK_DATA);
	if (data_start < 0) {
		/* ENXIO for SEEK_DATA means no file data anywhere. */
		if (errno == ENXIO)
			return true;
		reports_holes = false;
	}

	if (reports_holes) {
		data_end = lseek(fd, data_start, SEEK_HOLE);
		if (data_end < 0)
			reports_holes = false;
	}

	/* ...or just read everything if they don't. */
	if (!reports_holes) {
		data_start = 0;
		data_end = sb->st_size;
	}

	if (!direct_io) {
		posix_fadvise(fd, 0, sb->st_size, POSIX_FADV_SEQUENTIAL);
		posix_fadvise(fd, 0, sb->st_size, POSIX_FADV_WILLNEED);
	}
	/* Read the non-hole areas. */
	while (data_start < data_end) {
		start = data_start;

		if (direct_io && (start & (page_size - 1)))
			start &= ~(page_size - 1);
		count = min(IO_MAX_SIZE, data_end - start);
		if (direct_io && (count & (page_size - 1)))
			count = (count + page_size) & ~(page_size - 1);
		sz = pread64(fd, ctx->readbuf, count, start);
		if (sz < 0) {
			str_errno(ctx, descr);
			break;
		} else if (sz == 0) {
			str_error(ctx, descr,
_("Read zero bytes, expected %zu."),
					count);
			break;
		} else if (sz != count && start + sz != data_end) {
			str_warn(ctx, descr,
_("Short read of %zu bytes, expected %zu."),
					sz, count);
		}
		verified += sz;
		data_start = start + sz;

		if (xfs_scrub_excessive_errors(ctx)) {
			moveon = false;
			break;
		}

		if (data_start >= data_end && reports_holes) {
			data_start = lseek(fd, data_end, SEEK_DATA);
			if (data_start < 0) {
				if (errno != ENXIO)
					str_errno(ctx, descr);
				break;
			}
			data_end = lseek(fd, data_start, SEEK_HOLE);
			if (data_end < 0) {
				if (errno != ENXIO)
					str_errno(ctx, descr);
				break;
			}
		}
	}

	/* Turn off O_DIRECT. */
	if (direct_io) {
		flags = fcntl(fd, F_GETFL);
		error = fcntl(fd, F_SETFL, flags & ~O_DIRECT);
		if (error)
			str_errno(ctx, descr);
	}

	pthread_mutex_lock(&verified_lock);
	verified_bytes += verified;
	pthread_mutex_unlock(&verified_lock);

	return moveon;
}
