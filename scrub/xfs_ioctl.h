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
#ifndef XFS_IOCTL_H_
#define XFS_IOCTL_H_

struct xfs_inode_iter {
	/* Iterator function and arg. */
	bool			(*fn)(struct scrub_ctx *, xfs_agnumber_t,
				      struct xfs_handle *,
				      struct xfs_bstat *, void *);
	void			*arg;

	/* Should we keep scanning? */
	bool			moveon;
};

bool xfs_iterate_inodes(struct scrub_ctx *ctx, struct xfs_inode_iter *is,
		xfs_agnumber_t agno, void *fshandle, uint64_t first_ino,
		uint64_t last_ino);
bool xfs_can_iterate_inodes(struct scrub_ctx *ctx);

struct xfs_bmap_iter {
	/* Iterator function and arg. */
	bool			(*fn)(struct scrub_ctx *, const char *,
				      int, int, struct fsxattr *,
				      struct getbmapx *, void *);
	void			*arg;

	/* Description of the file descriptor. */
	const char		*descr;

	/* Should we keep scanning? */
	bool			moveon;
};

bool xfs_iterate_bmap(struct scrub_ctx *ctx, struct xfs_bmap_iter *xbi,
		int fd, int whichfork, struct getbmapx *key);
bool xfs_can_iterate_bmap(struct scrub_ctx *ctx);

struct xfs_fsmap_iter {
	/* Iterator function and arg. */
	bool			(*fn)(struct scrub_ctx *, const char *,
				      int, struct getfsmap *, void *);
	void			*arg;

	/* Should we keep scanning? */
	bool			moveon;
};

bool xfs_iterate_fsmap(struct scrub_ctx *ctx, struct xfs_fsmap_iter *xfi,
		int idx, struct getfsmap *keys);
bool xfs_can_iterate_fsmap(struct scrub_ctx *ctx);

/* Type info and names for the scrub types. */
enum scrub_type {
	ST_NONE,	/* disabled */
	ST_PERAG,	/* per-AG metadata */
	ST_FS,		/* per-FS metadata */
	ST_INODE,	/* per-inode metadata */
};
struct scrub_descr {
	const char	*name;
	enum scrub_type	type;
};

bool xfs_scrub_ag_metadata(struct scrub_ctx *ctx, xfs_agnumber_t agno,
		void *arg);
bool xfs_scrub_fs_metadata(struct scrub_ctx *ctx, void *arg);
bool xfs_scrub_inode_metadata(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_can_scrub_metadata(struct scrub_ctx *ctx);

#endif /* XFS_IOCTL_H_ */
