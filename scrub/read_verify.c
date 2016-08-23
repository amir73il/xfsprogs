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

/* Tolerate 64k holes in adjacent read verify requests. */
#define IO_BATCH_LOCALITY	(65536 >> BBSHIFT)

/* Create a thread pool to run read verifiers. */
void
read_verify_pool_init(
	struct read_verify_pool		*rvp,
	struct scrub_ctx		*ctx,
	void				*readbuf,
	size_t				readbufsz,
	size_t				min_io_sz,
	read_verify_ioend_fn_t		ioend_fn,
	read_verify_ioend_arg_free_fn_t	ioend_arg_free_fn,
	int				nproc)
{
	rvp->rvp_readbuf = readbuf;
	rvp->rvp_readbufsz = readbufsz;
	rvp->rvp_ctx = ctx;
	rvp->rvp_min_io_size = min_io_sz >> BBSHIFT;
	rvp->ioend_fn = ioend_fn;
	rvp->ioend_arg_free_fn = ioend_arg_free_fn;
	create_work_queue(&rvp->rvp_wq, (struct xfs_mount *)rvp, nproc);
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
	ssize_t				sz;
	ssize_t				len;

	rvp = (struct read_verify_pool *)wq->mp;
	while (rv->io_blockcount > 0) {
		len = min(rv->io_blockcount, rvp->rvp_readbufsz >> BBSHIFT);
		dbg_printf("pread %d %"PRIu64" %zu\n", rv->io_disk->d_fd,
				rv->io_startblock, len);
		sz = disk_read_verify(rv->io_disk, rvp->rvp_readbuf,
				rv->io_startblock, len);
		if (sz < 0) {
			dbg_printf("IOERR %d %"PRIu64" %zu\n",
					rv->io_disk->d_fd,
					rv->io_startblock, len);
			rvp->ioend_fn(rvp, rv->io_disk, rv->io_startblock,
					rvp->rvp_min_io_size,
					errno, rv->io_end_arg);
			len = rvp->rvp_min_io_size;
		}
		rv->io_startblock += len;
		rv->io_blockcount -= len;
	}

	if (rvp->ioend_arg_free_fn)
		rvp->ioend_arg_free_fn(rv->io_end_arg);
	free(rv);
}

/* Queue a read verify request. */
static void
read_verify_queue(
	struct read_verify_pool		*rvp,
	struct read_verify		*rv)
{
	struct read_verify		*tmp;

	dbg_printf("verify fd %d daddr %"PRIu64" len %"PRIu64"\n",
			rv->io_disk->d_fd, rv->io_startblock,
			rv->io_blockcount);

	tmp = malloc(sizeof(struct read_verify));
	if (!tmp) {
		rvp->ioend_fn(rvp, rv->io_disk, rv->io_startblock,
				rv->io_blockcount, errno, rv->io_end_arg);
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
	uint64_t			startblock,
	uint64_t			blockcount,
	void				*end_arg)
{
	uint64_t			ve_end;
	uint64_t			io_end;

	assert(rvp->rvp_readbuf);
	ve_end = startblock + blockcount;
	io_end = rv->io_startblock + rv->io_blockcount;

	/*
	 * If we have a stashed IO, we haven't changed fds, the error
	 * reporting is the same, and the two extents are close,
	 * we can combine them.
	 */
	if (rv->io_blockcount > 0 && disk == rv->io_disk &&
	    end_arg == rv->io_end_arg &&
	    ((startblock >= rv->io_startblock &&
	      startblock <= io_end + IO_BATCH_LOCALITY) ||
	     (rv->io_startblock >= startblock &&
	      rv->io_startblock <= ve_end + IO_BATCH_LOCALITY))) {
		rv->io_startblock = min(rv->io_startblock, startblock);
		rv->io_blockcount = max(ve_end, io_end) - rv->io_startblock;
	} else  {
		/* Otherwise, issue the stashed IO (if there is one) */
		if (rv->io_blockcount > 0)
			read_verify_queue(rvp, rv);

		/* Stash the new IO. */
		rv->io_disk = disk;
		rv->io_startblock = startblock;
		rv->io_blockcount = blockcount;
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
	if (rv->io_blockcount == 0)
		return;

	read_verify_queue(rvp, rv);
	rv->io_blockcount = 0;
}
