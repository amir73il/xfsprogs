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
#ifndef READ_VERIFY_H_
#define READ_VERIFY_H_

struct read_verify_pool;

typedef void (*read_verify_ioend_fn_t)(struct read_verify_pool *rvp,
		struct disk *disk, uint64_t start, uint64_t length,
		int error, void *arg);
typedef void (*read_verify_ioend_arg_free_fn_t)(void *arg);

struct read_verify_pool {
	struct work_queue	rvp_wq;
	struct scrub_ctx	*rvp_ctx;
	void			*rvp_readbuf;
	read_verify_ioend_fn_t	ioend_fn;
	read_verify_ioend_arg_free_fn_t	ioend_arg_free_fn;
	size_t			rvp_readbufsz;		/* bytes */
	size_t			rvp_min_io_size;	/* bytes */
	int			rvp_nproc;
};

bool read_verify_pool_init(struct read_verify_pool *rvp, struct scrub_ctx *ctx,
		void *readbuf, size_t readbufsz, size_t min_io_sz,
		read_verify_ioend_fn_t ioend_fn, unsigned int nproc);
void read_verify_pool_destroy(struct read_verify_pool *rvp);

struct read_verify {
	void			*io_end_arg;
	struct disk		*io_disk;
	uint64_t		io_start;	/* bytes */
	uint64_t		io_length;	/* bytes */
};

void read_verify_schedule(struct read_verify_pool *rvp, struct read_verify *rv,
		struct disk *disk, uint64_t start, uint64_t length,
		void *end_arg);
void read_verify_force(struct read_verify_pool *rvp, struct read_verify *rv);
unsigned long long read_verify_bytes(void);

#endif /* READ_VERIFY_H_ */
