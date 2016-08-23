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

/* inode iteration */
typedef bool (*xfs_inode_iter_fn)(struct scrub_ctx *ctx,
		struct xfs_handle *handle, struct xfs_bstat *bs, void *arg);
bool xfs_iterate_inodes(struct scrub_ctx *ctx, const char *descr,
		void *fshandle, uint64_t first_ino, uint64_t last_ino,
		xfs_inode_iter_fn fn, void *arg);
bool xfs_can_iterate_inodes(struct scrub_ctx *ctx);

/* inode fork block mapping */
struct xfs_bmap {
	uint64_t	bm_offset;	/* file offset of segment in bytes */
	uint64_t	bm_physical;	/* physical starting byte  */
	uint64_t	bm_length;	/* length of segment, bytes */
	uint32_t	bm_flags;	/* output flags */
};

typedef bool (*xfs_bmap_iter_fn)(struct scrub_ctx *ctx, const char *descr,
		int fd, int whichfork, struct fsxattr *fsx,
		struct xfs_bmap *bmap, void *arg);

bool xfs_iterate_bmap(struct scrub_ctx *ctx, const char *descr, int fd,
		int whichfork, struct xfs_bmap *key, xfs_bmap_iter_fn fn,
		void *arg);
bool xfs_can_iterate_bmap(struct scrub_ctx *ctx);

/* filesystem reverse mapping */
typedef bool (*xfs_fsmap_iter_fn)(struct scrub_ctx *ctx, const char *descr,
		struct fsmap *fsr, void *arg);
bool xfs_iterate_fsmap(struct scrub_ctx *ctx, const char *descr,
		struct fsmap *keys, xfs_fsmap_iter_fn fn, void *arg);
bool xfs_can_iterate_fsmap(struct scrub_ctx *ctx);

/* Online scrub and repair. */

bool xfs_scrub_ag_metadata(struct scrub_ctx *ctx, xfs_agnumber_t agno,
		struct list_head *repair_list);
bool xfs_scrub_fs_metadata(struct scrub_ctx *ctx,
		struct list_head *repair_list);
bool xfs_repair_metadata_list(struct scrub_ctx *ctx,
		struct list_head *repair_list);

bool xfs_can_scrub_fs_metadata(struct scrub_ctx *ctx);
bool xfs_can_scrub_inode(struct scrub_ctx *ctx);
bool xfs_can_scrub_bmap(struct scrub_ctx *ctx);
bool xfs_can_scrub_dir(struct scrub_ctx *ctx);
bool xfs_can_scrub_attr(struct scrub_ctx *ctx);
bool xfs_can_scrub_symlink(struct scrub_ctx *ctx);

bool xfs_scrub_inode_fields(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_data_fork(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_attr_fork(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_cow_fork(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_dir(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_attr(struct scrub_ctx *ctx, uint64_t ino, int fd);
bool xfs_scrub_symlink(struct scrub_ctx *ctx, uint64_t ino, int fd);

#endif /* XFS_IOCTL_H_ */
