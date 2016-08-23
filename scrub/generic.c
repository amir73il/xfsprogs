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
#include <linux/fiemap.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/xattr.h>
#include "disk.h"
#include "scrub.h"
#include "iocmd.h"
#include "../repair/threads.h"
#include "read_verify.h"
#include "bitmap.h"

/*
 * Generic Filesystem Scrub Strategy
 *
 * For a generic filesystem, we can only scrub the filesystem using the
 * generic VFS APIs that are accessible to userspace.  This requirement
 * reduces the effectiveness of the scrub because we can only scrub that
 * which we can find through the directory tree namespace -- we won't be
 * able to examine open unlinked files or any directory subtree that is
 * also a mountpoint.
 *
 * The "find geometry" phase collects statfs/statvfs information and
 * opens file descriptors to the mountpoint.  If the filesystem has a
 * block device, a file descriptor is opened to that as well.
 *
 * The VFS has no mechanism to scrub internal metadata or to iterate
 * inodes by inode number, so those phases do nothing.
 *
 * The "check directory structure" phase walks the directory tree
 * looking for inodes.  Each directory is processed separately by thread
 * pool workers.  For each entry in a directory, we scrub the following
 * pieces of metadata:
 *
 *     - The dirent inode number is compared against the fstatat output.
 *     - The dirent type code is also checked against the fstatat type.
 *     - If it's a symlink, the target is read but not validated.
 *     - If the entry is not a file or directory, the extended
 *       attributes names and values are read via llistxattr.
 *     - If the entry points to a file or directory, open the inode.
 *       If not, we're done with the entry.
 *     - The inode stat buffer is re-checked.
 *     - The extent maps for file data and extended attribute data are
 *       checked.
 *     - Extended attributes are read.
 *
 * The "verify data file integrity" phase re-walks the directory tree
 * for files.  If the filesystem supports FIEMAP and we have the block
 * device open, the data extents are read directly from disk.  This step
 * is optimized by buffering the disk extents in a bitmap and using the
 * bitmap to issue large IOs; if there are errors, those are recorded
 * and cross-referenced against the metadata to identify the affected
 * files with a second walk/FIEMAP run.  If FIEMAP is unavailable, it
 * falls back to using SEEK_DATA and SEEK_HOLE to direct-read file
 * contents.  If even that fails, direct-read the entire file.
 *
 * In the "check summary counters" phase, we tally up the blocks and
 * inodes we saw and compare that to the statfs output.  This gives the
 * user a rough estimate of how thorough the scrub was.
 */

#ifndef SEEK_DATA
# define SEEK_DATA	3	/* seek to the next data */
#endif

#ifndef SEEK_HOLE
# define SEEK_HOLE	4	/* seek to the next hole */
#endif

/* Routines to translate bad physical extents into file paths and offsets. */

/* Report if this extent overlaps a bad region. */
static bool
report_verify_inode_fiemap(
	struct scrub_ctx	*ctx,
	const char		*descr,
	struct fiemap_extent	*extent,
	void			*arg)
{
	struct bitmap	*tree = arg;

	/* Skip non-real/non-aligned extents. */
	if (extent->fe_flags & (FIEMAP_EXTENT_UNKNOWN |
				FIEMAP_EXTENT_DELALLOC |
				FIEMAP_EXTENT_ENCODED |
				FIEMAP_EXTENT_NOT_ALIGNED |
				FIEMAP_EXTENT_UNWRITTEN))
		return true;

	if (!bitmap_has_extent(tree, extent->fe_physical,
			extent->fe_length))
		return true;

	str_error(ctx, descr,
_("offset %llu failed read verification."), extent->fe_logical);

	return true;
}

/* Iterate the extent mappings of a file to report errors. */
static bool
report_verify_fd(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	void				*arg)
{
	/* data fork */
	fiemap(ctx, descr, fd, false, false, report_verify_inode_fiemap, arg);

	/* attr fork */
	fiemap(ctx, descr, fd, true, false, report_verify_inode_fiemap, arg);

	return true;
}

/* Scan the inode associated with a directory entry. */
static bool
report_verify_dirent(
	struct scrub_ctx	*ctx,
	const char		*path,
	int			dir_fd,
	struct dirent		*dirent,
	struct stat64		*sb,
	void			*arg)
{
	bool			moveon;
	int			fd;

	/* Ignore things we can't open. */
	if (!S_ISREG(sb->st_mode))
		return true;
	/* Ignore . and .. */
	if (dirent && (!strcmp(".", dirent->d_name) ||
		       !strcmp("..", dirent->d_name)))
		return true;

	/* Open the file */
	fd = dirent_open(dir_fd, dirent);
	if (fd < 0)
		return true;

	/* Go find the badness. */
	moveon = report_verify_fd(ctx, path, fd, arg);
	if (moveon)
		goto out;

out:
	close(fd);

	return moveon;
}

/* Given bad extent lists for the data device, find bad files. */
static bool
report_verify_errors(
	struct scrub_ctx		*ctx,
	struct bitmap		*d_bad)
{
	/* Scan the directory tree to get file paths. */
	return scan_fs_tree(ctx, NULL, report_verify_dirent, d_bad);
}

/* Phase 1 */
bool
generic_scan_fs(
	struct scrub_ctx	*ctx)
{
	/* If there's no disk device, forget FIEMAP. */
	if (!disk_is_open(&ctx->datadev))
		ctx->quirks &= ~(SCRUB_QUIRK_FIEMAP_WORKS |
				 SCRUB_QUIRK_FIEMAP_ATTR_WORKS |
				 SCRUB_QUIRK_FIBMAP_WORKS);

	return true;
}

bool
generic_cleanup(
	struct scrub_ctx	*ctx)
{
	/* Nothing to do here. */
	return true;
}

/* Phase 2 */
bool
generic_scan_metadata(
	struct scrub_ctx	*ctx)
{
	/* Nothing to do here. */
	return true;
}

/* Phase 3 */
bool
generic_scan_inodes(
	struct scrub_ctx	*ctx)
{
	/* Nothing to do here. */
	return true;
}

/* Phase 4 */

/* Check all entries in a directory. */
bool
generic_check_dir(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			dir_fd)
{
	/* Nothing to do here. */
	return true;
}

/* Check an extent for problems. */
static bool
check_fiemap_extent(
	struct scrub_ctx	*ctx,
	const char		*descr,
	struct fiemap_extent	*extent,
	void			*arg)
{
	unsigned long long	eofs;

	if (!disk_is_open(&ctx->datadev))
		return true;
	eofs = ctx->datadev.d_size;

	if (extent->fe_length == 0)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) has zero length."),
			extent->fe_physical,
			extent->fe_logical,
			extent->fe_length);
	if (extent->fe_physical > eofs)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) starts past end of filesystem at %llu."),
			extent->fe_physical,
			extent->fe_logical,
			extent->fe_length,
			eofs);
	if (extent->fe_physical + extent->fe_length > eofs ||
	    extent->fe_physical + extent->fe_length < extent->fe_physical)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) ends past end of filesystem at %llu."),
			extent->fe_physical,
			extent->fe_logical,
			extent->fe_length,
			eofs);
	if (extent->fe_logical + extent->fe_length < extent->fe_logical)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) overflows file offset."),
			extent->fe_physical,
			extent->fe_logical,
			extent->fe_length);
	return true;
}

/* Check an inode's extents. */
bool
generic_scan_extents(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	struct stat64		*sb,
	bool			attr_fork)
{
	/* FIEMAP only works for files. */
	if (!S_ISREG(sb->st_mode))
		return true;

	/* Don't invoke FIEMAP if we don't support it. */
	if (attr_fork && !scrub_has_fiemap_attr(ctx))
		return true;
	if (!attr_fork && !(scrub_has_fiemap(ctx) || scrub_has_fibmap(ctx)))
		return true;

	return fiemap(ctx, descr, fd, attr_fork, true,
			check_fiemap_extent, NULL);
}

/* Check the fields of an inode. */
bool
generic_check_inode(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	struct stat64		*sb)
{
	if (sb->st_nlink == 0)
		str_error(ctx, descr,
_("nlinks should not be 0."));

	return true;
}

/* Does this file have extended attributes? */
bool
file_has_xattrs(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd)
{
	ssize_t			buf_sz;

	buf_sz = flistxattr(fd, NULL, 0);
	if (buf_sz == 0)
		return false;
	else if (buf_sz < 0) {
		if (errno == EOPNOTSUPP || errno == ENODATA)
			return false;
		str_errno(ctx, descr);
		return false;
	}

	return true;
}

/* Try to read all the extended attributes. */
bool
generic_scan_xattrs(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd)
{
	char			*buf = NULL;
	char			*p;
	ssize_t			buf_sz;
	ssize_t			sz;
	ssize_t			val_sz;
	ssize_t			sz2;
	bool			moveon = true;

	buf_sz = flistxattr(fd, NULL, 0);
	if (buf_sz == 0)
		return true;
	else if (buf_sz < 0) {
		if (errno == EOPNOTSUPP || errno == ENODATA)
			return true;
		str_errno(ctx, descr);
		return true;
	}

	buf = malloc(buf_sz);
	if (!buf) {
		str_errno(ctx, descr);
		return false;
	}

	sz = flistxattr(fd, buf, buf_sz);
	if (sz < 0) {
		str_errno(ctx, descr);
		goto out;
	} else if (sz != buf_sz) {
		str_error(ctx, descr,
_("read %zu bytes of xattr names, expected %zu bytes."),
				sz, buf_sz);
	}

	/* Read all the attrs and values. */
	for (p = buf; p < buf + sz; p += strlen(p) + 1) {
		val_sz = fgetxattr(fd, p, NULL, 0);
		if (val_sz < 0) {
			if (errno != EOPNOTSUPP && errno != ENODATA)
				str_errno(ctx, descr);
			continue;
		}
		sz2 = fgetxattr(fd, p, ctx->readbuf, val_sz);
		if (sz2 < 0) {
			str_errno(ctx, descr);
			continue;
		} else if (sz2 != val_sz)
			str_error(ctx, descr,
_("read %zu bytes from xattr %s value, expected %zu bytes."),
					sz2, p, val_sz);
	}
out:
	free(buf);
	return moveon;
}

/* Try to read all the extended attributes of things that have no fd. */
bool
generic_scan_special_xattrs(
	struct scrub_ctx	*ctx,
	const char		*path)
{
	char			*buf = NULL;
	char			*p;
	ssize_t			buf_sz;
	ssize_t			sz;
	ssize_t			val_sz;
	ssize_t			sz2;
	bool			moveon = true;

	buf_sz = llistxattr(path, NULL, 0);
	if (buf_sz == -EOPNOTSUPP)
		return true;
	else if (buf_sz == 0)
		return true;
	else if (buf_sz < 0) {
		str_errno(ctx, path);
		return true;
	}

	buf = malloc(buf_sz);
	if (!buf) {
		str_errno(ctx, path);
		return false;
	}

	sz = llistxattr(path, buf, buf_sz);
	if (sz < 0) {
		str_errno(ctx, path);
		goto out;
	} else if (sz != buf_sz) {
		str_error(ctx, path,
_("read %zu bytes of xattr names, expected %zu bytes."),
				sz, buf_sz);
	}

	/* Read all the attrs and values. */
	for (p = buf; p < buf + sz; p += strlen(p) + 1) {
		val_sz = lgetxattr(path, p, NULL, 0);
		if (val_sz < 0) {
			str_errno(ctx, path);
			continue;
		}
		sz2 = lgetxattr(path, p, ctx->readbuf, val_sz);
		if (sz2 < 0) {
			str_errno(ctx, path);
			continue;
		} else if (sz2 != val_sz)
			str_error(ctx, path,
_("read %zu bytes from xattr %s value, expected %zu bytes."),
					sz2, p, val_sz);

		if (xfs_scrub_excessive_errors(ctx)) {
			moveon = false;
			break;
		}
	}
out:
	free(buf);
	return moveon;
}

/* Directory checking */
#define CHECK_TYPE(type) \
	case DT_##type: \
		if (!S_IS##type(sb->st_mode)) { \
			str_error(ctx, descr, \
_("dtype of block does not match mode 0x%x\n"), \
				sb->st_mode & S_IFMT); \
		} \
		break;

/* Ensure that the directory entry matches the stat info. */
static bool
generic_verify_dirent(
	struct scrub_ctx	*ctx,
	const char		*descr,
	struct dirent		*dirent,
	struct stat64		*sb)
{
	if (!scrub_has_unstable_inums(ctx) && dirent->d_ino != sb->st_ino) {
		str_error(ctx, descr,
_("inode numbers (%llu != %llu) do not match!"),
			(unsigned long long)dirent->d_ino,
			(unsigned long long)sb->st_ino);
	}

	switch (dirent->d_type) {
	case DT_UNKNOWN:
		break;
	CHECK_TYPE(BLK)
	CHECK_TYPE(CHR)
	CHECK_TYPE(DIR)
	CHECK_TYPE(FIFO)
	CHECK_TYPE(LNK)
	CHECK_TYPE(REG)
	CHECK_TYPE(SOCK)
	}

	return true;
}
#undef CHECK_TYPE

/* Scan the inode associated with a directory entry. */
static bool
check_dirent(
	struct scrub_ctx	*ctx,
	const char		*path,
	int			dir_fd,
	struct dirent		*dirent,
	struct stat64		*sb,
	void			*arg)
{
	struct stat64		fd_sb;
	static char		linkbuf[PATH_MAX + 1];
	ssize_t			len;
	bool			moveon;
	int			fd;
	int			error;

	/* No dirent for the rootdir; skip it. */
	if (!dirent)
		return true;

	/* Check the directory entry itself. */
	moveon = generic_verify_dirent(ctx, path, dirent, sb);
	if (!moveon)
		return moveon;

	/* If symlink, read the target value. */
	if (S_ISLNK(sb->st_mode)) {
		len = readlinkat(dir_fd, dirent->d_name, linkbuf,
				PATH_MAX);
		if (len < 0)
			str_errno(ctx, path);
		else if (len > sb->st_size)
			str_error(ctx, path,
_("read %zu bytes from a %zu byte symlink?"),
				len, sb->st_size);
	}

	/* Read the xattrs without a file descriptor. */
	if (S_ISSOCK(sb->st_mode) || S_ISFIFO(sb->st_mode) ||
	    S_ISBLK(sb->st_mode) || S_ISCHR(sb->st_mode) ||
	    S_ISLNK(sb->st_mode)) {
		moveon = ctx->ops->scan_special_xattrs(ctx, path);
		if (!moveon)
			return moveon;
	}

	/* If not dir or file, move on to the next dirent. */
	if (!S_ISDIR(sb->st_mode) && !S_ISREG(sb->st_mode))
		return true;

	/* Open the file */
	fd = openat(dir_fd, dirent->d_name,
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0) {
		if (errno != ENOENT)
			str_errno(ctx, path);
		return true;
	}

	/* Did the fstatat and the open race? */
	if (fstat64(fd, &fd_sb) < 0) {
		str_errno(ctx, path);
		goto close;
	}
	if (fd_sb.st_ino != sb->st_ino || fd_sb.st_dev != sb->st_dev)
		str_warn(ctx, path,
_("inode changed out from under us!"));

	/* Check the inode. */
	moveon = ctx->ops->check_inode(ctx, path, fd, &fd_sb);
	if (!moveon)
		goto close;

	/* Scan the extent maps. */
	moveon = ctx->ops->scan_extents(ctx, path, fd, &fd_sb, false);
	if (!moveon)
		goto close;
	if (file_has_xattrs(ctx, path, fd)) {
		moveon = ctx->ops->scan_extents(ctx, path, fd, &fd_sb, true);
		if (!moveon)
			goto close;
	}

	/* Read all the extended attributes. */
	moveon = ctx->ops->scan_xattrs(ctx, path, fd);
	if (!moveon)
		goto close;

close:
	/* Close file. */
	error = close(fd);
	if (error)
		str_errno(ctx, path);

	return moveon;
}

/*
 * Check all the entries in a directory.
 */
bool
generic_check_directory(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			*pfd)
{
	struct stat64		sb;
	DIR			*dir;
	struct dirent		*dirent;
	bool			moveon = true;
	int			fd = *pfd;
	int			error;

	/* Iterate the directory entries. */
	dir = fdopendir(fd);
	if (!dir) {
		str_errno(ctx, descr);
		return true;
	}
	rewinddir(dir);

	/* Iterate every directory entry. */
	for (dirent = readdir(dir);
	     dirent != NULL;
	     dirent = readdir(dir)) {
		error = fstatat64(fd, dirent->d_name, &sb,
				AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);
		if (error) {
			str_errno(ctx, descr);
			break;
		}

		/* Ignore files on other filesystems. */
		if (sb.st_dev != ctx->mnt_sb.st_dev)
			continue;

		/* Check the type codes. */
		moveon = generic_verify_dirent(ctx, descr, dirent, &sb);
		if (!moveon)
			break;

		if (xfs_scrub_excessive_errors(ctx)) {
			moveon = false;
			break;
		}
	}

	/* Close dir, go away. */
	error = closedir(dir);
	if (error)
		str_errno(ctx, descr);
	*pfd = -1;
	return moveon;
}

/* Adapter for the check_dir thing. */
static bool
check_dir(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			dir_fd,
	void			*arg)
{
	return ctx->ops->check_dir(ctx, descr, dir_fd);
}

/* Traverse the directory tree. */
bool
generic_scan_fs_tree(
	struct scrub_ctx	*ctx)
{
	return scan_fs_tree(ctx, check_dir, check_dirent, NULL);
}

/* Phase 5 */

struct read_verify_files {
	struct scrub_ctx	*ctx;
	struct bitmap		good;		/* bytes */
	struct bitmap		bad;		/* bytes */
	struct read_verify_pool	rvp;
	struct read_verify	rv;
	bool			use_fiemap;
};

/* Handle an io error while read verifying an extent. */
void
read_verify_fiemap_ioerr(
	struct read_verify_pool		*rvp,
	struct disk			*disk,
	uint64_t			start,
	uint64_t			length,
	int				error,
	void				*arg)
{
	struct read_verify_files	*rvf = arg;

	bitmap_add(&rvf->bad, start, length);
}

/* Check an extent for data integrity problems. */
bool
read_verify_fiemap_extent(
	struct scrub_ctx		*ctx,
	const char			*descr,
	struct fiemap_extent		*extent,
	void				*arg)
{
	struct read_verify_files	*rvf = arg;

	/* Skip non-real/non-aligned extents. */
	if (extent->fe_flags & (FIEMAP_EXTENT_UNKNOWN |
				FIEMAP_EXTENT_DELALLOC |
				FIEMAP_EXTENT_ENCODED |
				FIEMAP_EXTENT_NOT_ALIGNED |
				FIEMAP_EXTENT_UNWRITTEN))
		return true;

	return bitmap_add(&rvf->good, extent->fe_physical,
			extent->fe_length);
}

/* Scan the inode associated with a directory entry. */
static bool
read_verify_dirent(
	struct scrub_ctx		*ctx,
	const char			*path,
	int				dir_fd,
	struct dirent			*dirent,
	struct stat64			*sb,
	void				*arg)
{
	struct stat64			fd_sb;
	struct read_verify_files	*rvf = arg;
	bool				moveon = true;
	int				fd;
	int				error;

	/* If not file, move on to the next dirent. */
	if (!S_ISREG(sb->st_mode))
		return true;

	/* Open the file */
	fd = openat(dir_fd, dirent->d_name,
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0) {
		if (errno != ENOENT)
			str_errno(ctx, path);
		return true;
	}

	/* Did the fstatat and the open race? */
	if (fstat64(fd, &fd_sb) < 0) {
		str_errno(ctx, path);
		goto close;
	}
	if (fd_sb.st_ino != sb->st_ino || fd_sb.st_dev != sb->st_dev)
		str_warn(ctx, path,
_("inode changed out from under us!"));

	/*
	 * Either record the file extent map data for one big push later,
	 * or read the file data the regular way.
	 */
	if (rvf->use_fiemap)
		moveon = fiemap(ctx, path, fd, false, false,
				read_verify_fiemap_extent, rvf);
	else
		moveon = ctx->ops->read_file(ctx, path, fd, &fd_sb);
	if (!moveon)
		goto close;

close:
	/* Close file. */
	error = close(fd);
	if (error)
		str_errno(ctx, path);

	return moveon;
}

static bool
schedule_read_verify(
	uint64_t			start,
	uint64_t			length,
	void				*arg)
{
	struct read_verify_files	*rvf = arg;

	read_verify_schedule(&rvf->rvp, &rvf->rv, &rvf->ctx->datadev,
			start, length, rvf);
	return true;
}

/* Can we FIEMAP every block in a file? */
static bool
can_fiemap_all_file_blocks(
	struct scrub_ctx		*ctx)
{
	return disk_is_open(&ctx->datadev) &&
		scrub_has_fiemap(ctx) && scrub_has_fiemap_attr(ctx);
}

/* Scan all the data blocks, using FIEMAP to figure out what to verify. */
bool
generic_scan_blocks(
	struct scrub_ctx		*ctx)
{
	struct read_verify_files	rvf = {0};
	bool				moveon;

	if (!scrub_data)
		return true;

	rvf.ctx = ctx;

	/* If FIEMAP is unavailable, just use regular file pread. */
	if (!can_fiemap_all_file_blocks(ctx))
		return scan_fs_tree(ctx, NULL, read_verify_dirent, &rvf);

	rvf.use_fiemap = true;
	moveon = bitmap_init(&rvf.good);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	moveon = bitmap_init(&rvf.bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_good;
	}

	/* Collect all the extent maps. */
	moveon = scan_fs_tree(ctx, NULL, read_verify_dirent, &rvf);
	if (!moveon)
		goto out_bad;

	/* Run all the IO in batches. */
	moveon = read_verify_pool_init(&rvf.rvp, ctx, ctx->readbuf, IO_MAX_SIZE,
			ctx->mnt_sf.f_frsize, read_verify_fiemap_ioerr,
			disk_heads(&ctx->datadev));
	if (!moveon)
		goto out_bad;
	moveon = bitmap_iterate(&rvf.good, schedule_read_verify, &rvf);
	if (!moveon)
		goto out_pool;
	read_verify_force(&rvf.rvp, &rvf.rv);
	read_verify_pool_destroy(&rvf.rvp);

	/* Scan the whole dir tree to see what matches the bad extents. */
	if (!bitmap_empty(&rvf.bad))
		moveon = report_verify_errors(ctx, &rvf.bad);

	bitmap_free(&rvf.bad);
	bitmap_free(&rvf.good);
	return moveon;

out_pool:
	read_verify_pool_destroy(&rvf.rvp);
out_bad:
	bitmap_free(&rvf.bad);
out_good:
	bitmap_free(&rvf.good);

	return moveon;
}

/* Phase 6 */
struct summary_counts {
	pthread_mutex_t		lock;
	struct bitmap	dext;
	struct bitmap	inob;	/* inode bitmap */
	unsigned long long	inodes;	/* number of inodes */
	unsigned long long	bytes;	/* bytes used */
};

struct inode_fork_summary {
	struct bitmap	*tree;
	unsigned long long	bytes;
};

/* Record data block extents in a bitmap. */
bool
generic_record_inode_summary_fiemap(
	struct scrub_ctx		*ctx,
	const char			*descr,
	struct fiemap_extent		*extent,
	void				*arg)
{
	struct inode_fork_summary	*ifs = arg;

	/* Skip non-real/non-aligned extents. */
	if (extent->fe_flags & (FIEMAP_EXTENT_UNKNOWN |
				FIEMAP_EXTENT_DELALLOC |
				FIEMAP_EXTENT_ENCODED |
				FIEMAP_EXTENT_NOT_ALIGNED))
		return true;

	bitmap_add(ifs->tree, extent->fe_physical, extent->fe_length);
	ifs->bytes += extent->fe_length;

	return true;
}

/* Record the presence of an inode and its block usage. */
static bool
generic_record_inode_summary(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				dir_fd,
	struct dirent			*dirent,
	struct stat64			*sb,
	void				*arg)
{
	struct summary_counts		*summary = arg;
	struct stat64			fd_sb;
	struct inode_fork_summary	ifs;
	unsigned long long		bs_bytes;
	int				fd;
	bool				has;
	bool				moveon = true;

	if (dirent && (strcmp(dirent->d_name, ".") == 0 ||
		       strcmp(dirent->d_name, "..") == 0))
		return true;

	/* Detect hardlinked files. */
	moveon = bitmap_test_and_set(&summary->inob, sb->st_ino, &has);
	if (!moveon)
		return moveon;
	if (has)
		return true;

	bs_bytes = sb->st_blocks << BBSHIFT;

	/* Record the inode.  If it's not a file, record the data usage too. */
	pthread_mutex_lock(&summary->lock);
	summary->inodes++;

	/*
	 * We can use fiemap and dext to figure out the correct block usage
	 * for files that might share blocks.  If any of those conditions
	 * are not met (non-file, fs doesn't support reflink, fiemap doesn't
	 * work) then we just assume that the inode is the sole owner of its
	 * blocks and use that to calculate the block usage.
	 */
	if (!can_fiemap_all_file_blocks(ctx) || !scrub_has_shared_blocks(ctx) ||
	    !S_ISREG(sb->st_mode)) {
		summary->bytes += bs_bytes;
		pthread_mutex_unlock(&summary->lock);
		return true;
	}
	pthread_mutex_unlock(&summary->lock);

	/* Open the file */
	fd = dirent_open(dir_fd, dirent);
	if (fd < 0) {
		if (errno != ENOENT)
			str_errno(ctx, descr);
		return true;
	}

	/* Did the fstatat and the open race? */
	if (fstat64(fd, &fd_sb) < 0) {
		str_errno(ctx, descr);
		goto close;
	}

	if (fd_sb.st_ino != sb->st_ino || fd_sb.st_dev != sb->st_dev)
		str_warn(ctx, descr,
_("inode changed out from under us!"));

	ifs.tree = &summary->dext;
	ifs.bytes = 0;
	moveon = fiemap(ctx, descr, fd, false, false,
			generic_record_inode_summary_fiemap, &ifs);
	if (!moveon)
		goto out_nofiemap;
	if (file_has_xattrs(ctx, descr, fd)) {
		moveon = fiemap(ctx, descr, fd, true, false,
				generic_record_inode_summary_fiemap, &ifs);
		if (!moveon)
			goto out_nofiemap;
	}

	/*
	 * bs_bytes tracks the number of bytes assigned to this file
	 * for data, xattrs, and block mapping metadata.  ifs.bytes tracks
	 * the data and xattr storage space used, so the diff between the
	 * two is the space used for block mapping metadata.  Add that to
	 * the data usage.
	 */
out_nofiemap:
	pthread_mutex_lock(&summary->lock);
	summary->bytes += bs_bytes - ifs.bytes;
	pthread_mutex_unlock(&summary->lock);

close:
	close(fd);
	return moveon;
}

/* Sum the bytes in each extent. */
static bool
generic_summary_count_helper(
	uint64_t			start,
	uint64_t			length,
	void				*arg)
{
	unsigned long long		*count = arg;

	*count += length;
	return true;
}

/* Traverse the directory tree, counting inodes & blocks. */
bool
generic_check_summary(
	struct scrub_ctx	*ctx)
{
	struct summary_counts	summary = {0};
	struct stat64		sb;
	struct statvfs		sfs;
	unsigned long long	fd;
	unsigned long long	fi;
	unsigned long long	sd;
	unsigned long long	si;
	unsigned long long	absdiff;
	bool			complain = false;
	bool			moveon;
	int			error;

	pthread_mutex_init(&summary.lock, NULL);

	/* Flush everything out to disk before we start counting. */
	error = syncfs(ctx->mnt_fd);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	/* Get the rootdir's summary stats. */
	error = fstat64(ctx->mnt_fd, &sb);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	moveon = bitmap_init(&summary.dext);
	if (!moveon)
		return moveon;

	moveon = bitmap_init(&summary.inob);
	if (!moveon)
		return moveon;

	/* Scan the rest of the filesystem. */
	moveon = scan_fs_tree(ctx, NULL, generic_record_inode_summary,
			&summary);
	if (!moveon)
		return moveon;

	/* Summarize extent tree results. */
	moveon = bitmap_iterate(&summary.dext,
			generic_summary_count_helper, &summary.bytes);
	if (!moveon)
		return moveon;

	bitmap_free(&summary.inob);
	bitmap_free(&summary.dext);

	/* Compare to statfs results. */
	error = fstatvfs(ctx->mnt_fd, &sfs);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	/* Report on what we found. */
	fd = (sfs.f_blocks - sfs.f_bfree) * sfs.f_frsize;
	fi = sfs.f_files - sfs.f_ffree;
	sd = summary.bytes;
	si = summary.inodes;

	/*
	 * Complain if the counts are off by more than 10%, unless
	 * the inaccuracy is less than 32MB worth of blocks or 100 inodes.
	 * Ignore zero counters.
	 */
	absdiff = 1ULL << 25;
	if (fd)
		complain = !within_range(ctx, sd, fd, absdiff, 1, 10,
				_("data blocks"));
	if (fi)
		complain |= !within_range(ctx, si, fi, 100, 1, 10, _("inodes"));

	if (complain || verbose) {
		double		b, i;
		char		*bu, *iu;

		b = auto_space_units(fd, &bu);
		i = auto_units(fi, &iu);
		printf(_("%.1f%s data used;  %.1f%s inodes used.\n"),
				b, bu, i, iu);
		b = auto_space_units(sd, &bu);
		i = auto_units(si, &iu);
		printf(_("%.1f%s data found; %.1f%s inodes found.\n"),
				b, bu, i, iu);
	}

	return true;
}

/* Phase 7: Preening filesystem. */
bool
generic_preen_fs(
	struct scrub_ctx		*ctx)
{
	fstrim(ctx);
	return true;
}

struct scrub_ops generic_scrub_ops = {
	.name			= "generic",
	.cleanup		= generic_cleanup,
	.scan_fs		= generic_scan_fs,
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
