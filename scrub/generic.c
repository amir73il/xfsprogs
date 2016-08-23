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
#include "extent.h"

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
	struct extent_tree	*tree = arg;

	/* Skip non-real/non-aligned extents. */
	if (extent->fe_flags & (FIEMAP_EXTENT_UNKNOWN |
				FIEMAP_EXTENT_DELALLOC |
				FIEMAP_EXTENT_ENCODED |
				FIEMAP_EXTENT_NOT_ALIGNED |
				FIEMAP_EXTENT_UNWRITTEN))
		return true;

	if (!extent_tree_has_extent(tree, extent->fe_physical >> BBSHIFT,
			extent->fe_length >> BBSHIFT))
		return true;

	str_error(ctx, descr,
_("offset %llu failed read verification."),
			extent->fe_logical >> BBSHIFT);

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
	if (!strcmp(".", dirent->d_name) || !strcmp("..", dirent->d_name))
		return true;

	/* Open the file */
	fd = openat(dir_fd, dirent->d_name,
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
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
	struct extent_tree		*d_bad)
{
	/* Scan the directory tree to get file paths. */
	return scan_fs_tree(ctx, NULL, report_verify_dirent, d_bad);
}

/* Phase 1 */
bool
generic_scan_fs(
	struct scrub_ctx	*ctx)
{
	/* Nothing to do here. */
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
	unsigned long		quirks;

	pthread_mutex_lock(&ctx->lock);
	quirks = ctx->quirks;
	pthread_mutex_unlock(&ctx->lock);

	if (quirks & SCRUB_QUIRK_IGNORE_STATFS_BLOCKS)
		eofs = ctx->datadev.d_nrsectors;
	else
		eofs = ctx->mnt_sf.f_blocks * ctx->mnt_sf.f_frsize;

	if (extent->fe_length == 0)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) has zero length."),
			extent->fe_physical >> BBSHIFT,
			extent->fe_logical >> BBSHIFT,
			extent->fe_length >> BBSHIFT);
	if (extent->fe_physical > eofs)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) starts past end of filesystem at %llu."),
			extent->fe_physical >> BBSHIFT,
			extent->fe_logical >> BBSHIFT,
			extent->fe_length >> BBSHIFT,
			eofs >> BBSHIFT);
	if (extent->fe_physical + extent->fe_length > eofs ||
	    extent->fe_physical + extent->fe_length <
			extent->fe_physical)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) ends past end of filesystem at %llu."),
			extent->fe_physical >> BBSHIFT,
			extent->fe_logical >> BBSHIFT,
			extent->fe_length >> BBSHIFT,
			eofs >> BBSHIFT);
	if (extent->fe_logical + extent->fe_length <
			extent->fe_logical)
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) overflows file offset."),
			extent->fe_physical >> BBSHIFT,
			extent->fe_logical >> BBSHIFT,
			extent->fe_length >> BBSHIFT);
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
	if (buf_sz == -EOPNOTSUPP)
		return true;
	else if (buf_sz == 0)
		return true;
	else if (buf_sz < 0) {
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
			if (errno != ENODATA)
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
	if (dirent->d_ino != sb->st_ino) {
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
	static char		linkbuf[PATH_MAX];
	ssize_t			len;
	bool			moveon;
	int			fd;
	int			error;

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
		else if (len != sb->st_size)
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
	moveon = ctx->ops->scan_extents(ctx, path, fd, &fd_sb, true);
	if (!moveon)
		goto close;

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

struct read_verify_fiemap {
	struct scrub_ctx	*ctx;
	struct extent_tree	good;
	struct extent_tree	bad;
	struct read_verify_pool	rvp;
	struct read_verify	rv;
	bool			(*fiemap_fn)(struct scrub_ctx *,
					     const char *,
					     struct fiemap_extent *,
					     void *);
};

/* Handle an io error while read verifying an extent. */
void
read_verify_fiemap_ioerr(
	struct read_verify_pool		*rvp,
	struct disk			*disk,
	uint64_t			startblock,
	uint64_t			blockcount,
	int				error,
	void				*arg)
{
	struct read_verify_fiemap	*rvf = arg;

	extent_tree_add(&rvf->bad, startblock, blockcount);
}

/* Check an extent for data integrity problems. */
bool
read_verify_fiemap_extent(
	struct scrub_ctx		*ctx,
	const char			*descr,
	struct fiemap_extent		*extent,
	void				*arg)
{
	struct read_verify_fiemap	*rvf = arg;

	/* Skip non-real/non-aligned extents. */
	if (extent->fe_flags & (FIEMAP_EXTENT_UNKNOWN |
				FIEMAP_EXTENT_DELALLOC |
				FIEMAP_EXTENT_ENCODED |
				FIEMAP_EXTENT_NOT_ALIGNED |
				FIEMAP_EXTENT_UNWRITTEN))
		return true;

	return extent_tree_add(&rvf->good, extent->fe_physical >> BBSHIFT,
			extent->fe_length >> BBSHIFT);
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
	struct read_verify_fiemap	*rvf = arg;
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
	 * Read all the file data.  If we have the block device open
	 * we'll try to use FIEMAP data to read-verify the physical
	 * data blocks.  If that doesn't work, we'll use the generic
	 * seek-based read_file to verify the file data.
	 */
	if (disk_is_open(&ctx->datadev))
		moveon = fiemap(ctx, path, fd, false, false, rvf->fiemap_fn,
			rvf);
	else
		moveon = false;
	if (moveon)
		goto close;
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
	struct read_verify_fiemap	*rvf = arg;

	read_verify_schedule(&rvf->rvp, &rvf->rv, &rvf->ctx->datadev,
			start, length, rvf);
	return true;
}

/* Scan all the data blocks, using FIEMAP to figure out what to verify. */
bool
generic_scan_blocks(
	struct scrub_ctx		*ctx)
{
	struct read_verify_fiemap	rvf;
	bool				moveon;

	if (!scrub_data)
		return true;

	memset(&rvf, 0, sizeof(rvf));
	rvf.ctx = ctx;
	moveon = extent_tree_init(&rvf.good);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	moveon = extent_tree_init(&rvf.bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_good;
	}

	/* Collect all the extent maps. */
	rvf.fiemap_fn = read_verify_fiemap_extent;
	moveon = scan_fs_tree(ctx, NULL, read_verify_dirent, &rvf);
	if (!moveon)
		goto out_bad;

	/* Run all the IO in batches. */
	read_verify_pool_init(&rvf.rvp, ctx, ctx->readbuf, IO_MAX_SIZE,
			ctx->mnt_sf.f_frsize, read_verify_fiemap_ioerr,
			NULL, scrub_nproc(ctx));
	moveon = extent_tree_iterate(&rvf.good, schedule_read_verify, &rvf);
	if (!moveon)
		goto out_pool;
	read_verify_force(&rvf.rvp, &rvf.rv);
	read_verify_pool_destroy(&rvf.rvp);

	/* Scan the whole dir tree to see what matches the bad extents. */
	if (!extent_tree_empty(&rvf.bad))
		moveon = report_verify_errors(ctx, &rvf.bad);

	extent_tree_free(&rvf.bad);
	extent_tree_free(&rvf.good);
	return moveon;

out_pool:
	read_verify_pool_destroy(&rvf.rvp);
out_bad:
	extent_tree_free(&rvf.bad);
out_good:
	extent_tree_free(&rvf.good);

	return moveon;
}

/* Read all the data in a file. */
bool
generic_read_file(
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
	bool			reports_holes = true;
	bool			direct_io = false;
	int			flags;
	int			error;

	/* Can we set O_DIRECT? */
	flags = fcntl(fd, F_GETFL);
	error = fcntl(fd, F_SETFL, flags | O_DIRECT);
	if (!error)
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
		if (sz < 0)
			str_errno(ctx, descr);
		else if (sz == 0) {
			str_error(ctx, descr,
_("Read zero bytes, expected %zu."),
					count);
			break;
		} else if (sz != count && start + sz != data_end) {
			str_warn(ctx, descr,
_("Short read of %zu bytes, expected %zu."),
					sz, count);
		}
		data_start = start + sz;

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

	return true;
}

/* Phase 6 */
struct summary_counts {
	pthread_mutex_t		lock;
	unsigned long long	inodes;	/* number of inodes */
	unsigned long long	blocks;	/* 512b blocks */
};

/* Record the presence of an inode and its block usage. */
static bool
record_inode_summary(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			dir_fd,
	struct dirent		*dirent,
	struct stat64		*sb,
	void			*arg)
{
	struct summary_counts	*summary = arg;

	if (strcmp(dirent->d_name, ".") == 0 ||
	    strcmp(dirent->d_name, "..") == 0)
		return true;

	pthread_mutex_lock(&summary->lock);
	summary->inodes++;
	summary->blocks += sb->st_blocks;
	pthread_mutex_unlock(&summary->lock);

	return true;
}

/* Traverse the directory tree, counting inodes & blocks. */
bool
generic_check_summary(
	struct scrub_ctx	*ctx)
{
	struct summary_counts	summary;
	struct stat64		sb;
	struct statvfs		sfs;
	unsigned long long	fd;
	unsigned long long	fi;
	unsigned long long	sd;
	unsigned long long	si;
	unsigned long long	absdiff;
	bool			complain;
	bool			moveon;
	int			error;

	pthread_mutex_init(&summary.lock, NULL);
	summary.inodes = 0;
	summary.blocks = 0;

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

	/* Scan the rest of the filesystem. */
	moveon = scan_fs_tree(ctx, NULL, record_inode_summary, &summary);
	if (!moveon)
		return moveon;

	/* Compare to statfs results. */
	error = fstatvfs(ctx->mnt_fd, &sfs);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	/* Report on what we found. */
	fd = (sfs.f_blocks - sfs.f_bfree) * sfs.f_frsize >> (BBSHIFT + 1),
	fi = sfs.f_files - sfs.f_ffree;
	sd = summary.blocks >> 1;
	si = summary.inodes;

	/*
	 * Complain if the counts are off by more than 10%, unless
	 * the inaccuracy is less than 32MB worth of blocks or 100 inodes.
	 */
	absdiff = (1ULL << 25) / sfs.f_bsize;
	complain = !within_range(ctx, sd, fd, absdiff, 1, 10, _("data blocks"));
	complain |= !within_range(ctx, si, fi, 100, 1, 10, _("inodes"));

	if (complain || verbose) {
		double		b, i;
		char		*bu, *iu;

		b = auto_space_units(fd, &bu);
		i = auto_units(fi, &iu);
		printf(_("%.1f%s blocks used;  %.2f%s inodes used.\n"),
				b, bu, i, iu);
		b = auto_space_units(sd, &bu);
		i = auto_units(si, &iu);
		printf(_("%.1f%s blocks found; %.2f%s inodes found.\n"),
				b, bu, i, iu);
	}

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
	.read_file		= generic_read_file,
	.scan_blocks		= generic_scan_blocks,
	.scan_fs_tree		= generic_scan_fs_tree,
};
