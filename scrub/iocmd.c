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
#include "../repair/threads.h"
#include "disk.h"
#include "scrub.h"
#include "iocmd.h"

#define NR_EXTENTS	512

/* Scan a filesystem tree. */
struct scan_fs_tree {
	unsigned int		nr_dirs;
	pthread_mutex_t		lock;
	pthread_cond_t		wakeup;
	struct stat64		root_sb;
	bool			moveon;
	bool			(*dir_fn)(struct scrub_ctx *, const char *,
					  int, void *);
	bool			(*dirent_fn)(struct scrub_ctx *, const char *,
					     int, struct dirent *,
					     struct stat64 *, void *);
	void			*arg;
};

/* Per-work-item scan context. */
struct scan_fs_tree_dir {
	char			*path;
	struct scan_fs_tree	*sft;
};

/* Scan a directory sub tree. */
static void
scan_fs_dir(
	struct work_queue	*wq,
	xfs_agnumber_t		agno,
	void			*arg)
{
	struct scrub_ctx	*ctx = (struct scrub_ctx *)wq->mp;
	struct scan_fs_tree_dir	*sftd = arg;
	struct scan_fs_tree	*sft = sftd->sft;
	DIR			*dir;
	struct dirent		*dirent;
	char			newpath[PATH_MAX];
	struct scan_fs_tree_dir	*new_sftd;
	struct stat64		sb;
	int			dir_fd;
	int			error;

	/* Open the directory. */
	dir_fd = open(sftd->path, O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (dir_fd < 0) {
		if (errno != ENOENT)
			str_errno(ctx, sftd->path);
		goto out;
	}

	/* Caller-specific directory checks. */
	if (sft->dir_fn && !sft->dir_fn(ctx, sftd->path, dir_fd, sft->arg)) {
		sft->moveon = false;
		goto out;
	}

	/* Iterate the directory entries. */
	dir = fdopendir(dir_fd);
	if (!dir) {
		str_errno(ctx, sftd->path);
		goto out;
	}
	rewinddir(dir);
	for (dirent = readdir(dir); dirent != NULL; dirent = readdir(dir)) {
		snprintf(newpath, PATH_MAX, "%s/%s", sftd->path,
				dirent->d_name);

		/* Get the stat info for this directory entry. */
		error = fstatat64(dir_fd, dirent->d_name, &sb,
				AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW);
		if (error) {
			str_errno(ctx, newpath);
			continue;
		}

		/* Ignore files on other filesystems. */
		if (sb.st_dev != sft->root_sb.st_dev)
			continue;

		/* Caller-specific directory entry function. */
		if (!sft->dirent_fn(ctx, newpath, dir_fd, dirent, &sb,
				sft->arg)) {
			sft->moveon = false;
			break;
		}

		/* If directory, call ourselves recursively. */
		if (S_ISDIR(sb.st_mode) && strcmp(".", dirent->d_name) &&
		    strcmp("..", dirent->d_name)) {
			new_sftd = malloc(sizeof(struct scan_fs_tree_dir));
			if (!new_sftd) {
				str_errno(ctx, newpath);
				sft->moveon = false;
				break;
			}
			new_sftd->path = strdup(newpath);
			new_sftd->sft = sft;
			pthread_mutex_lock(&sft->lock);
			sft->nr_dirs++;
			pthread_mutex_unlock(&sft->lock);
			queue_work(wq, scan_fs_dir, 0, new_sftd);
		}
	}

	/* Close dir, go away. */
	error = closedir(dir);
	if (error)
		str_errno(ctx, sftd->path);

out:
	pthread_mutex_lock(&sft->lock);
	sft->nr_dirs--;
	if (sft->nr_dirs == 0)
		pthread_cond_signal(&sft->wakeup);
	pthread_mutex_unlock(&sft->lock);

	free(sftd->path);
	free(sftd);
}

/* Scan the entire filesystem. */
bool
scan_fs_tree(
	struct scrub_ctx	*ctx,
	bool			(*dir_fn)(struct scrub_ctx *, const char *,
					  int, void *),
	bool			(*dirent_fn)(struct scrub_ctx *, const char *,
						int, struct dirent *,
						struct stat64 *, void *),
	void			*arg)
{
	struct work_queue	wq;
	struct scan_fs_tree	sft;
	struct scan_fs_tree_dir	*sftd;

	sft.moveon = true;
	sft.nr_dirs = 1;
	sft.root_sb = ctx->mnt_sb;
	sft.dir_fn = dir_fn;
	sft.dirent_fn = dirent_fn;
	sft.arg = arg;
	pthread_mutex_init(&sft.lock, NULL);
	pthread_cond_init(&sft.wakeup, NULL);

	sftd = malloc(sizeof(struct scan_fs_tree_dir));
	if (!sftd) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}
	sftd->path = strdup(ctx->mntpoint);
	sftd->sft = &sft;

	create_work_queue(&wq, (struct xfs_mount *)ctx, scrub_nproc(ctx));
	queue_work(&wq, scan_fs_dir, 0, sftd);

	pthread_mutex_lock(&sft.lock);
	pthread_cond_wait(&sft.wakeup, &sft.lock);
	assert(sft.nr_dirs == 0);
	pthread_mutex_unlock(&sft.lock);
	destroy_work_queue(&wq);

	return sft.moveon;
}

/* Check an inode's extents... the hard way. */
static bool
fibmap(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	bool			(*fn)(struct scrub_ctx *, const char *,
				      struct fiemap_extent *, void *),
	void			*arg)
{
	struct stat64		sb;
	struct fiemap_extent	extent;
	unsigned int		blk;
	unsigned int		b;
	off_t			numblocks;
	bool			moveon = true;
	int			error;

	pthread_mutex_lock(&ctx->lock);
	if (!(ctx->quirks & SCRUB_QUIRK_FIBMAP_WORKS)) {
		pthread_mutex_unlock(&ctx->lock);
		return true;
	}
	pthread_mutex_unlock(&ctx->lock);

	error = fstat64(fd, &sb);
	if (error) {
		str_errno(ctx, descr);
		return false;
	}

	numblocks = (sb.st_size + sb.st_blksize - 1) / sb.st_blksize;
	if (numblocks > UINT_MAX)
		numblocks = UINT_MAX;
	for (blk = 0; blk < numblocks; blk++) {
		b = blk;
		error = ioctl(fd, FIBMAP, &b);
		if (error) {
			if (errno == EOPNOTSUPP || errno == EINVAL) {
				str_warn(ctx, descr,
_("data block FIEMAP/FIBMAP not supported, will not check extent map."));
				pthread_mutex_lock(&ctx->lock);
				ctx->quirks &= ~SCRUB_QUIRK_FIBMAP_WORKS;
				pthread_mutex_unlock(&ctx->lock);
				return true;
			}
			str_errno(ctx, descr);
			continue;
		}
		extent.fe_physical = b * sb.st_blksize;
		extent.fe_logical = blk * sb.st_blksize;
		extent.fe_length = sb.st_blksize;
		extent.fe_flags = 0;
		moveon = fn(ctx, descr, &extent, arg);
		if (!moveon)
			break;
	}

	return moveon;
}

/* Call the FIEMAP ioctl on a file. */
bool
fiemap(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	bool			attr_fork,
	bool			use_fibmap,
	bool			(*fn)(struct scrub_ctx *, const char *,
				      struct fiemap_extent *, void *),
	void			*arg)
{
	struct fiemap		*fiemap;
	struct fiemap_extent	*extent;
	size_t			sz;
	__u64			next_logical;
	unsigned long		quirks;
	bool			moveon = true;
	bool			last = false;
	unsigned int		i;
	int			error;

	pthread_mutex_lock(&ctx->lock);
	quirks = ctx->quirks;
	pthread_mutex_unlock(&ctx->lock);
	if (!attr_fork && !(quirks & SCRUB_QUIRK_FIEMAP_WORKS))
		return use_fibmap ? fibmap(ctx, descr, fd, fn, arg) : false;
	else if (attr_fork && !(quirks & SCRUB_QUIRK_FIEMAP_ATTR_WORKS))
		return true;

	sz = sizeof(struct fiemap) + sizeof(struct fiemap_extent) * NR_EXTENTS;
	fiemap = calloc(sz, 1);
	if (!fiemap) {
		str_errno(ctx, descr);
		return false;
	}

	fiemap->fm_length = ~0ULL;
	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	if (attr_fork)
		fiemap->fm_flags |= FIEMAP_FLAG_XATTR;
	fiemap->fm_extent_count = NR_EXTENTS;
	fiemap->fm_reserved = 0;
	next_logical = 0;

	while (!last) {
		fiemap->fm_start = next_logical;
		error = ioctl(fd, FS_IOC_FIEMAP, (unsigned long)fiemap);
		if (error < 0 && (errno == EOPNOTSUPP || errno == EBADR)) {
			if (attr_fork) {
				str_warn(ctx, descr,
_("extended attribute FIEMAP not supported, will not check extent map."));
				pthread_mutex_lock(&ctx->lock);
				ctx->quirks &= ~SCRUB_QUIRK_FIEMAP_ATTR_WORKS;
				pthread_mutex_unlock(&ctx->lock);
			} else {
				pthread_mutex_lock(&ctx->lock);
				ctx->quirks &= ~SCRUB_QUIRK_FIEMAP_WORKS;
				pthread_mutex_unlock(&ctx->lock);
			}
			break;
		}
		if (error < 0) {
			str_errno(ctx, descr);
			break;
		}

		/* No more extents to map, exit */
		if (!fiemap->fm_mapped_extents)
			break;

		for (i = 0; i < fiemap->fm_mapped_extents; i++) {
			extent = &fiemap->fm_extents[i];

			moveon = fn(ctx, descr, extent, arg);
			if (!moveon)
				goto out;

			next_logical = extent->fe_logical + extent->fe_length;
			if (extent->fe_flags & FIEMAP_EXTENT_LAST)
				last = true;
		}
	}

out:
	free(fiemap);
	return moveon;
}
