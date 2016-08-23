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
#ifndef IOCMD_H_
#define IOCMD_H_

struct fiemap_extent;

bool
scan_fs_tree(
	struct scrub_ctx	*ctx,
	bool			(*dir_fn)(struct scrub_ctx *, const char *,
					  int, void *),
	bool			(*dirent_fn)(struct scrub_ctx *, const char *,
						int, struct dirent *,
						struct stat64 *, void *),
	void			*arg);

bool
fiemap(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	bool			attr_fork,
	bool			fibmap,
	bool			(*fn)(struct scrub_ctx *, const char *,
				      struct fiemap_extent *, void *),
	void			*arg);

void
fstrim(
	struct scrub_ctx	*ctx);

#endif /* IOCMD_H_ */
