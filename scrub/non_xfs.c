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
#include <dirent.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "disk.h"
#include "scrub.h"

/* Stub scrubbers for non-XFS filesystems. */

/* Read the btrfs geometry. */
static bool
btrfs_scan_fs(
	struct scrub_ctx		*ctx)
{
	/*
	 * btrfs is a volume manager, so we can't get meaningful block numbers
	 * out of FIEMAP/FIBMAP.  It also checksums data, so raw device access
	 * for file verify is impossible.  btrfs also supports reflink.
	 */
	ctx->quirks |= SCRUB_QUIRK_SHARED_BLOCKS;
	disk_close(&ctx->datadev);
	return generic_scan_fs(ctx);
}

/* Scrub all disk blocks using the btrfs scrub command. */
static bool
btrfs_scan_blocks(
	struct scrub_ctx		*ctx)
{
	pid_t				pid;
	pid_t				rpid;
	char				*args[] = {"btrfs", "scrub", "start",
						   "-B", "-f", "-q",
						   ctx->mntpoint, NULL, NULL};
	int				status;
	int				err;

	if (ctx->mode == SCRUB_MODE_DRY_RUN) {
		args[6] = "-n";
		args[7] = ctx->mntpoint;
	}

	pid = fork();
	if (pid < 0)
		str_errno(ctx, ctx->mntpoint);
	else if (pid == 0) {
		status = execvp(args[0], args);
		exit(255);
	} else {
		rpid = waitpid(pid, &status, 0);
		while (rpid >= 0 && rpid != pid && !WIFEXITED(status) &&
				!WIFSIGNALED(status)) {
			rpid = waitpid(pid, &status, 0);
		}
		if (rpid < 0)
			str_errno(ctx, ctx->mntpoint);
		else if (WIFSIGNALED(status))
			str_error(ctx, ctx->mntpoint,
_("btrfs scrub died, signal %d"),
					WTERMSIG(status));
		else if (WIFEXITED(status)) {
			err = WEXITSTATUS(status);
			if (err == 0)
				return true;
			else if (err == 255)
				str_error(ctx, ctx->mntpoint,
_("btrfs scrub failed to run."));
			else
				str_error(ctx, ctx->mntpoint,
_("btrfs scrub signalled corruption, error %d"),
						err);
		}
	}

	return true;
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
	.read_file		= read_verify_file,
	.scan_blocks		= btrfs_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
	.preen_fs		= generic_preen_fs,
};

/*
 * Generic FS scanner for filesystems that support shared blocks.
 */
static bool
scan_fs_shared_blocks(
	struct scrub_ctx		*ctx)
{
	ctx->quirks |= SCRUB_QUIRK_SHARED_BLOCKS;
	return generic_scan_fs(ctx);
}

/* shared block filesystem profiles */
struct scrub_ops shared_block_fs_scrub_ops = {
	.name			= "shared block generic",
	.aliases		= "ocfs2\0",
	.cleanup		= generic_cleanup,
	.scan_fs		= scan_fs_shared_blocks,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= read_verify_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
	.preen_fs		= generic_preen_fs,
};

/*
 * Generic FS scan for filesystems that don't present stable inode numbers
 * between the directory entry and the stat buffer.
 */
static bool
scan_fs_unstable_inum(
	struct scrub_ctx		*ctx)
{
	/*
	 * HFS+ implements hard links by creating a special hidden file
	 * that redirects to the real file, so the inode numbers reported
	 * in the dirent and the fstat buffers don't necessarily match.
	 *
	 * iso9660/vfat don't have stable dirent -> inode numbers.
	 */
	ctx->quirks |= SCRUB_QUIRK_UNSTABLE_INUM;
	return generic_scan_fs(ctx);
}

/* unstable inum filesystem profile */
struct scrub_ops unstable_inum_fs_scrub_ops = {
	.name			= "unstable inum generic",
	.aliases		= "hfsplus\0iso9660\0vfat\0",
	.cleanup		= generic_cleanup,
	.scan_fs		= scan_fs_unstable_inum,
	.scan_inodes		= generic_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= generic_scan_extents,
	.scan_xattrs		= generic_scan_xattrs,
	.scan_special_xattrs	= generic_scan_special_xattrs,
	.scan_metadata		= generic_scan_metadata,
	.check_summary		= generic_check_summary,
	.read_file		= read_verify_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
	.preen_fs		= generic_preen_fs,
};
