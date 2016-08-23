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
#include "disk.h"
#include "scrub.h"

/* Stub scrubbers for non-XFS filesystems. */

/* Read the ext4 geometry. */
static bool
ext4_scan_fs(
	struct scrub_ctx		*ctx)
{
	/*
	 * ext* underreports the filesystem block size by the journal
	 * length, so we can't verify FIEMAP info against the statvfs
	 * counters.
	 */
	ctx->quirks |= SCRUB_QUIRK_IGNORE_STATFS_BLOCKS;
	return generic_scan_fs(ctx);
}

/* extN profile */
struct scrub_ops ext2_scrub_ops = {
	.name			= "ext2",
	.cleanup		= generic_cleanup,
	.scan_fs		= ext4_scan_fs,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= generic_read_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
};
struct scrub_ops ext3_scrub_ops = {
	.name			= "ext3",
	.cleanup		= generic_cleanup,
	.scan_fs		= ext4_scan_fs,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= generic_read_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
};
struct scrub_ops ext4_scrub_ops = {
	.name			= "ext4",
	.cleanup		= generic_cleanup,
	.scan_fs		= ext4_scan_fs,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= generic_read_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
};

/* Read the btrfs geometry. */
static bool
btrfs_scan_fs(
	struct scrub_ctx		*ctx)
{
	/*
	 * btrfs is a volume manager, so we can't get meaningful block numbers
	 * out of FIEMAP/FIBMAP.  It also checksums data, so raw device access
	 * for file verify is impossible.
	 */
	ctx->quirks = SCRUB_QUIRK_IGNORE_STATFS_BLOCKS;
	disk_close(&ctx->datadev);
	return generic_scan_fs(ctx);
}

/* btrfs profile */
struct scrub_ops btrfs_scrub_ops = {
	.name			= "btrfs",
	.cleanup		= generic_cleanup,
	.scan_fs		= btrfs_scan_fs,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= generic_read_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
};
