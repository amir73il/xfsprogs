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
#include <attr/attributes.h>
#include "disk.h"
#include "scrub.h"
#include "../repair/threads.h"
#include "handle.h"
#include "path.h"
#include "xfs_ioctl.h"
#include "read_verify.h"
#include "extent.h"
#include "iocmd.h"

/*
 * XFS Scrubbing Strategy
 *
 * The XFS scrubber is much more thorough than the generic scrubber
 * because we can use custom XFS ioctls to probe more deeply into the
 * internals of the filesystem.  Furthermore, we can take advantage of
 * scrubbing ioctls to check all the records stored in a metadata btree
 * and cross-reference those records against the other btrees.
 *
 * The "find geometry" phase queries XFS for the filesystem geometry.
 * The block devices for the data, realtime, and log devices are opened.
 * Kernel ioctls are queried to see if they are implemented, and a data
 * file read-verify strategy is selected.
 *
 * In the "check internal metadata" phase, we call the SCRUB_METADATA
 * ioctl to check the filesystem's internal per-AG btrees.  This
 * includes the AG superblock, AGF, AGFL, and AGI headers, freespace
 * btrees, the regular and free inode btrees, the reverse mapping
 * btrees, and the reference counting btrees.  If the realtime device is
 * enabled, the realtime bitmap and reverse mapping btrees are enabled.
 * Each AG (and the realtime device) has its metadata checked in a
 * separate thread for better performance.
 *
 * The "scan inodes" phase uses BULKSTAT to scan all the inodes in an
 * AG in disk order.  From the BULKSTAT information, a file handle is
 * constructed and the following items are checked:
 *
 *     - If it's a symlink, the target is read but not validated.
 *     - Bulkstat data is checked.
 *     - If the inode is a file or a directory, a file descriptor is
 *       opened to pin the inode and for further analysis.
 *     - Extended attribute names and values are read via the file
 *       handle.  If this fails and we have a file descriptor open, we
 *       retry with the generic extended attribute APIs.
 *     - If the inode is not a file or directory, we're done.
 *     - Extent maps are scanned to ensure that the records make sense.
 *       We also use the SCRUB_METADATA ioctl for better checking of the
 *       block mapping records.
 *     - If the inode is a directory, open the directory and check that
 *       the dirent type code and inode numbers match the stat output.
 *
 * Multiple threads are started to check each the inodes of each AG in
 * parallel.
 *
 * If BULKSTAT is available, we can skip the "check directory structure"
 * phase because directories were checked during the inode scan.
 * Otherwise, the generic directory structure check is used.
 *
 * In the "verify data file integrity" phase, we can employ multiple
 * strategies to read-verify the data blocks:
 *
 *     - If GETFSMAP is available, use it to read the reverse-mappings of
 *       all AGs and issue direct-reads of the underlying disk blocks.
 *       We rely on the underlying storage to have checksummed the data
 *       blocks appropriately.
 *     - If GETBMAPX is available, we use BULKSTAT (or a directory tree
 *       walk) to iterate all inodes and issue direct-reads of the
 *       underlying data.  Similar to the generic read-verify, the data
 *       extents are buffered through a bitmap, which is used to issue
 *       larger IOs.  Errors are recorded and cross-referenced through
 *       a second BULKSTAT/GETBMAPX run.
 *     - Otherwise, call the generic handler to verify file data.
 *
 * Multiple threads are started to check each AG in parallel.  A
 * separate thread pool is used to handle the direct reads.
 *
 * In the "check summary counters" phase, use GETFSMAP to tally up the
 * blocks and BULKSTAT to tally up the inodes we saw and compare that to
 * the statfs output.  This gives the user a rough estimate of how
 * thorough the scrub was.
 */

/* Routines to scrub an XFS filesystem. */

enum data_scrub_type {
	DS_NOSCRUB,		/* no data scrub */
	DS_READ,		/* generic_scan_blocks */
	DS_BULKSTAT_READ,	/* bulkstat and generic_file_read */
	DS_BMAPX,		/* bulkstat, getbmapx, and read_verify */
	DS_FSMAP,		/* getfsmap and read_verify */
};

struct xfs_scrub_ctx {
	struct xfs_fsop_geom	geo;
	struct fs_path		fsinfo;
	unsigned int		agblklog;
	unsigned int		blocklog;
	unsigned int		inodelog;
	unsigned int		inopblog;
	struct disk		datadev;
	struct disk		logdev;
	struct disk		rtdev;
	void			*fshandle;
	size_t			fshandle_len;
	bool			kernel_scrub;	/* have kernel scrub assist? */
	bool			fsmap;		/* have getfsmap ioctl? */
	bool			bulkstat;	/* have bulkstat ioctl? */
	bool			bmapx;		/* have bmapx ioctl? */
	bool			checked_xattrs;	/* did we check all xattrs? */
	bool			parent_ptrs;	/* have parent pointers? */
	struct read_verify_pool	rvp;
	enum data_scrub_type	data_scrubber;
};

/* Find the fd for a given device identifier. */
static struct disk *
xfs_dev_to_disk(
	struct xfs_scrub_ctx	*xctx,
	dev_t			dev)
{
	if (dev == xctx->fsinfo.fs_datadev)
		return &xctx->datadev;
	else if (dev == xctx->fsinfo.fs_logdev)
		return &xctx->logdev;
	else if (dev == xctx->fsinfo.fs_rtdev)
		return &xctx->rtdev;
	assert(0);
}

/* Find the device major/minor for a given file descriptor. */
static dev_t
xfs_disk_to_dev(
	struct xfs_scrub_ctx	*xctx,
	struct disk		*disk)
{
	if (disk == &xctx->datadev)
		return xctx->fsinfo.fs_datadev;
	else if (disk == &xctx->logdev)
		return xctx->fsinfo.fs_logdev;
	else if (disk == &xctx->rtdev)
		return xctx->fsinfo.fs_rtdev;
	assert(0);
}

struct owner_decode {
	uint64_t		owner;
	const char		*descr;
};

static const struct owner_decode special_owners[] = {
	{FMV_OWN_FREE,		"free space"},
	{FMV_OWN_UNKNOWN,	"unknown owner"},
	{FMV_OWN_FS,		"static FS metadata"},
	{FMV_OWN_LOG,		"journalling log"},
	{FMV_OWN_AG,		"per-AG metadata"},
	{FMV_OWN_INOBT,		"inode btree blocks"},
	{FMV_OWN_INODES,	"inodes"},
	{FMV_OWN_REFC,		"refcount btree"},
	{FMV_OWN_COW,		"CoW staging"},
	{FMV_OWN_DEFECTIVE,	"bad blocks"},
	{0, NULL},
};

/* Decode a special owner. */
static const char *
xfs_decode_special_owner(
	uint64_t			owner)
{
	const struct owner_decode	*od = special_owners;

	while (od->descr) {
		if (od->owner == owner)
			return od->descr;
		od++;
	}

	return NULL;
}

/* BULKSTAT wrapper routines. */

/* Scan all the inodes in an AG. */
static void
xfs_scan_ag_inodes(
	struct work_queue	*wq,
	xfs_agnumber_t		agno,
	void			*arg)
{
	struct xfs_inode_iter	*is = (struct xfs_inode_iter *)arg;
	struct scrub_ctx	*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	uint64_t		ag_ino;
	uint64_t		next_ag_ino;
	bool			moveon;

	ag_ino = (__u64)agno << (xctx->inopblog + xctx->agblklog);
	next_ag_ino = (__u64)(agno + 1) << (xctx->inopblog + xctx->agblklog);

	moveon = xfs_iterate_inodes(ctx, is, agno, xctx->fshandle, ag_ino,
			next_ag_ino - 1);
	if (!moveon)
		is->moveon = false;
}

/* Scan all the inodes in a filesystem. */
static bool
xfs_scan_all_inodes(
	struct scrub_ctx	*ctx,
	bool			(*fn)(struct scrub_ctx *, xfs_agnumber_t,
				      struct xfs_handle *,
				      struct xfs_bstat *, void *),
	void			*arg)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	xfs_agnumber_t		agno;
	struct work_queue	wq;
	struct xfs_inode_iter	is;

	if (!xctx->bulkstat)
		return true;

	is.moveon = true;
	is.fn = fn;
	is.arg = arg;

	create_work_queue(&wq, (struct xfs_mount *)ctx, scrub_nproc(ctx));
	for (agno = 0; agno < xctx->geo.agcount; agno++)
		queue_work(&wq, xfs_scan_ag_inodes, agno, &is);
	destroy_work_queue(&wq);

	return is.moveon;
}

/* GETFSMAP wrappers routines. */

/* Iterate all the reverse mappings of an AG. */
static void
xfs_scan_ag_blocks(
	struct work_queue	*wq,
	xfs_agnumber_t		agno,
	void			*arg)
{
	struct scrub_ctx	*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct xfs_fsmap_iter	*xfi = arg;
	struct getfsmap		map[2];
	off64_t			bbperag;
	bool			moveon;

	bbperag = (off64_t)xctx->geo.agblocks *
		  (off64_t)xctx->geo.blocksize / BBSIZE;

	memset(map, 0, sizeof(*map) * 2);
	map->fmv_device = xctx->fsinfo.fs_datadev;
	map->fmv_block = agno * bbperag;
	(map + 1)->fmv_device = xctx->fsinfo.fs_datadev;
	(map + 1)->fmv_block = ((agno + 1) * bbperag) - 1;
	(map + 1)->fmv_owner = ULLONG_MAX;
	(map + 1)->fmv_offset = ULLONG_MAX;
	(map + 1)->fmv_oflags = UINT_MAX;

	moveon = xfs_iterate_fsmap(ctx, xfi, agno, map);
	if (!moveon)
		xfi->moveon = false;
}

/* Iterate all the reverse mappings of a standalone device. */
static void
xfs_scan_dev_blocks(
	struct scrub_ctx	*ctx,
	int			idx,
	struct xfs_fsmap_iter	*xfi,
	dev_t			dev)
{
	struct getfsmap		map[2];
	bool			moveon;

	memset(map, 0, sizeof(*map) * 2);
	map->fmv_device = dev;
	(map + 1)->fmv_device = dev;
	(map + 1)->fmv_block = ULLONG_MAX;
	(map + 1)->fmv_owner = ULLONG_MAX;
	(map + 1)->fmv_offset = ULLONG_MAX;
	(map + 1)->fmv_oflags = UINT_MAX;

	moveon = xfs_iterate_fsmap(ctx, xfi, idx, map);
	if (!moveon)
		xfi->moveon = false;
}

/* Iterate all the reverse mappings of the realtime device. */
static void
xfs_scan_rt_blocks(
	struct work_queue	*wq,
	xfs_agnumber_t		agno,
	void			*arg)
{
	struct scrub_ctx	*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct xfs_fsmap_iter	*xfi = arg;

	xfs_scan_dev_blocks(ctx, agno, xfi, xctx->fsinfo.fs_rtdev);
}

/* Iterate all the reverse mappings of the log device. */
static void
xfs_scan_log_blocks(
	struct work_queue	*wq,
	xfs_agnumber_t		agno,
	void			*arg)
{
	struct scrub_ctx	*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct xfs_fsmap_iter	*xfi = arg;

	xfs_scan_dev_blocks(ctx, agno, xfi, xctx->fsinfo.fs_logdev);
}

/* Scan all the blocks in a filesystem. */
static bool
xfs_scan_all_blocks(
	struct scrub_ctx	*ctx,
	bool			(*fn)(struct scrub_ctx *, const char *, int,
				      struct getfsmap *, void *),
	void			*arg)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	xfs_agnumber_t		agno;
	struct work_queue	wq;
	struct xfs_fsmap_iter	bs;

	bs.moveon = true;
	bs.fn = fn;
	bs.arg = arg;

	create_work_queue(&wq, (struct xfs_mount *)ctx, scrub_nproc(ctx));
	if (xctx->fsinfo.fs_rt)
		queue_work(&wq, xfs_scan_rt_blocks, -1, &bs);
	if (xctx->fsinfo.fs_log)
		queue_work(&wq, xfs_scan_log_blocks, -2, &bs);
	for (agno = 0; agno < xctx->geo.agcount; agno++)
		queue_work(&wq, xfs_scan_ag_blocks, agno, &bs);
	destroy_work_queue(&wq);

	return bs.moveon;
}

/* Routines to translate bad physical extents into file paths and offsets. */

struct xfs_verify_error_info {
	struct extent_tree		*d_bad;
	struct extent_tree		*r_bad;
};

/* Report if this extent overlaps a bad region. */
static bool
xfs_report_verify_inode_bmap(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	int				whichfork,
	struct fsxattr			*fsx,
	struct getbmapx			*bmap,
	void				*arg)
{
	struct xfs_verify_error_info	*vei = arg;
	struct extent_tree		*tree;

	/*
	 * Only do data scrubbing if the extent is neither unwritten nor
	 * delalloc.
	 */
	if (bmap->bmv_oflags & (BMV_OF_PREALLOC | BMV_OF_DELALLOC))
		return true;

	if (fsx->fsx_xflags & FS_XFLAG_REALTIME)
		tree = vei->r_bad;
	else
		tree = vei->d_bad;

	if (!extent_tree_has_extent(tree, bmap->bmv_block, bmap->bmv_length))
		return true;

	str_error(ctx, descr,
_("offset %llu failed read verification."),
			bmap->bmv_offset);
	return true;
}

/* Iterate the extent mappings of a file to report errors. */
static bool
xfs_report_verify_fd(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	void				*arg)
{
	struct xfs_bmap_iter		xbi;
	struct getbmapx			key;
	bool				moveon;

	xbi.moveon = true;
	xbi.arg = arg;
	xbi.descr = descr;
	xbi.fn = xfs_report_verify_inode_bmap;

	/* data fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_DATA_FORK, &key);
	if (!moveon || !xbi.moveon)
		return false;

	/* attr fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_ATTR_FORK, &key);
	if (!moveon || !xbi.moveon)
		return false;
	return true;
}

/* Report read verify errors in unlinked (but still open) files. */
static bool
xfs_report_verify_inode(
	struct scrub_ctx		*ctx,
	xfs_agnumber_t			agno,
	struct xfs_handle		*handle,
	struct xfs_bstat		*bstat,
	void				*arg)
{
	char				descr[DESCR_BUFSZ];
	bool				moveon;
	int				fd;

	/* Ignore linked files and things we can't open. */
	if (bstat->bs_nlink != 0)
		return true;
	if (!S_ISREG(bstat->bs_mode) && !S_ISDIR(bstat->bs_mode))
		return true;

	/* Try to open the inode. */
	fd = open_by_fshandle(handle, sizeof(*handle),
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0)
		return true;

	/* Go find the badness. */
	snprintf(descr, DESCR_BUFSZ, _("inode %llu (unlinked)"), bstat->bs_ino);
	moveon = xfs_report_verify_fd(ctx, descr, fd, arg);
	if (moveon)
		goto out;

out:
	close(fd);
	return moveon;
}

/* Scan the inode associated with a directory entry. */
static bool
xfs_report_verify_dirent(
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
	if (!S_ISREG(sb->st_mode) && !S_ISDIR(sb->st_mode))
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
	moveon = xfs_report_verify_fd(ctx, path, fd, arg);
	if (moveon)
		goto out;

out:
	close(fd);

	return moveon;
}

/* Given bad extent lists for the data & rtdev, find bad files. */
static bool
xfs_report_verify_errors(
	struct scrub_ctx		*ctx,
	struct extent_tree		*d_bad,
	struct extent_tree		*r_bad)
{
	struct xfs_verify_error_info	vei;
	bool				moveon;

	vei.d_bad = d_bad;
	vei.r_bad = r_bad;

	/* Scan the directory tree to get file paths. */
	moveon = scan_fs_tree(ctx, NULL, xfs_report_verify_dirent, &vei);
	if (!moveon)
		return false;

	/* Scan for unlinked files. */
	return xfs_scan_all_inodes(ctx, xfs_report_verify_inode, &vei);
}

/* Phase 1 */

/* Clean up the XFS-specific state data. */
static bool
xfs_cleanup(
	struct scrub_ctx	*ctx)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	if (!xctx)
		goto out;
	if (xctx->fshandle)
		free_handle(xctx->fshandle, xctx->fshandle_len);
	disk_close(&xctx->rtdev);
	disk_close(&xctx->logdev);
	disk_close(&xctx->datadev);
	free(ctx->priv);
	ctx->priv = NULL;

out:
	return generic_cleanup(ctx);
}

/* Read the XFS geometry. */
static bool
xfs_scan_fs(
	struct scrub_ctx		*ctx)
{
	struct xfs_scrub_ctx		*xctx;
	struct fs_path			*fsp;
	int				error;

	if (!platform_test_xfs_fd(ctx->mnt_fd)) {
		str_error(ctx, ctx->mntpoint,
_("Does not appear to be an XFS filesystem!"));
		return false;
	}

	xctx = calloc(1, sizeof(struct xfs_scrub_ctx));
	if (!ctx) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}
	xctx->datadev.d_fd = xctx->logdev.d_fd = xctx->rtdev.d_fd = -1;

	/* Retrieve XFS geometry. */
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_FSGEOMETRY,
			&xctx->geo);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		goto err;
	}
	ctx->priv = xctx;

	xctx->agblklog = libxfs_log2_roundup(xctx->geo.agblocks);
	xctx->blocklog = libxfs_highbit32(xctx->geo.blocksize);
	xctx->inodelog = libxfs_highbit32(xctx->geo.inodesize);
	xctx->inopblog = xctx->blocklog - xctx->inodelog;

	error = path_to_fshandle(ctx->mntpoint, &xctx->fshandle,
			&xctx->fshandle_len);
	if (error) {
		perror(_("getting fshandle"));
		goto err;
	}

	/* Do we have bulkstat? */
	xctx->bulkstat = xfs_can_iterate_inodes(ctx);
	if (!xctx->bulkstat)
		str_info(ctx, ctx->mntpoint,
_("Kernel lacks BULKSTAT; scrub will be incomplete."));

	/* Do we have kernel-assisted scrubbing? */
	xctx->kernel_scrub = xfs_can_scrub_metadata(ctx);
	if (!xctx->kernel_scrub)
		str_info(ctx, ctx->mntpoint,
_("Kernel cannot help scrub metadata; scrub will be incomplete."));

	/* Do we have getbmapx? */
	xctx->bmapx = xfs_can_iterate_bmap(ctx);
	if (!xctx->bmapx)
		str_info(ctx, ctx->mntpoint,
_("Kernel lacks GETBMAPX; scrub will be less efficient."));

	/* Do we have getfsmap? */
	xctx->fsmap = xfs_can_iterate_fsmap(ctx);
	if (!xctx->fsmap && scrub_data)
		str_info(ctx, ctx->mntpoint,
_("Kernel lacks GETFSMAP; scrub will be less efficient."));

	/* Do we have parent pointers? */
	xctx->parent_ptrs = false; /* NOPE */

	/* Go find the XFS devices if we have a usable fsmap. */
	fs_table_initialise(0, NULL, 0, NULL);
	errno = 0;
	fsp = fs_table_lookup(ctx->mntpoint, FS_MOUNT_POINT);
	if (!fsp) {
		str_error(ctx, ctx->mntpoint,
_("Unable to find XFS information."));
		goto err;
	}
	memcpy(&xctx->fsinfo, fsp, sizeof(struct fs_path));

	/* Did we find the log and rt devices, if they're present? */
	if (xctx->geo.logstart == 0 && xctx->fsinfo.fs_log == NULL) {
		str_error(ctx, ctx->mntpoint,
_("Unable to find log device path."));
		goto err;
	}
	if (xctx->geo.rtblocks && xctx->fsinfo.fs_rt == NULL) {
		str_error(ctx, ctx->mntpoint,
_("Unable to find realtime device path."));
		goto err;
	}

	/* Open the raw devices. */
	error = disk_open(xctx->fsinfo.fs_name, &xctx->datadev);
	if (error) {
		str_errno(ctx, xctx->fsinfo.fs_name);
		xctx->fsmap = false;
	}
	ctx->nr_io_threads = disk_heads(&xctx->datadev);

	if (xctx->fsinfo.fs_log) {
		error = disk_open(xctx->fsinfo.fs_log, &xctx->logdev);
		if (error) {
			str_errno(ctx, xctx->fsinfo.fs_name);
			xctx->fsmap = false;
		}
	}
	if (xctx->fsinfo.fs_rt) {
		error = disk_open(xctx->fsinfo.fs_rt, &xctx->rtdev);
		if (error) {
			str_errno(ctx, xctx->fsinfo.fs_name);
			xctx->fsmap = false;
		}
	}
	if (xctx->geo.sunit)
		ctx->nr_io_threads = xctx->geo.swidth / xctx->geo.sunit;

	/* Figure out who gets to scrub data extents... */
	if (scrub_data) {
		if (xctx->fsmap)
			xctx->data_scrubber = DS_FSMAP;
		else if (xctx->bmapx)
			xctx->data_scrubber = DS_BMAPX;
		else  if (xctx->bulkstat)
			xctx->data_scrubber = DS_BULKSTAT_READ;
		else
			xctx->data_scrubber = DS_READ;
	} else
		xctx->data_scrubber = DS_NOSCRUB;

	return generic_scan_fs(ctx);
err:
	xfs_cleanup(ctx);
	return false;
}

/* Phase 2 */

/* Scrub each AG's metadata btrees. */
static void
xfs_scan_ag_metadata(
	struct work_queue		*wq,
	xfs_agnumber_t			agno,
	void				*arg)
{
	struct scrub_ctx		*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	bool				*pmoveon = arg;
	bool				moveon;

	if (!xctx->kernel_scrub)
		return;

	moveon = xfs_scrub_ag_metadata(ctx, agno, arg);
	if (!moveon)
		*pmoveon = false;
}

/* Scrub whole-FS metadata btrees. */
static void
xfs_scan_fs_metadata(
	struct work_queue		*wq,
	xfs_agnumber_t			agno,
	void				*arg)
{
	struct scrub_ctx		*ctx = (struct scrub_ctx *)wq->mp;
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	bool				*pmoveon = arg;
	bool				moveon;

	if (!xctx->kernel_scrub)
		return;

	moveon = xfs_scrub_fs_metadata(ctx, arg);
	if (!moveon)
		*pmoveon = false;
}

/* Try to scan metadata via sysfs. */
static bool
xfs_scan_metadata(
	struct scrub_ctx	*ctx)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	xfs_agnumber_t		agno;
	struct work_queue	wq;
	bool			moveon = true;

	create_work_queue(&wq, (struct xfs_mount *)ctx, scrub_nproc(ctx));
	queue_work(&wq, xfs_scan_fs_metadata, 0, &moveon);
	for (agno = 0; agno < xctx->geo.agcount; agno++)
		queue_work(&wq, xfs_scan_ag_metadata, agno, &moveon);
	destroy_work_queue(&wq);

	return moveon;
}

/* Phase 3 */

/* Scrub an inode extent, report if it's bad. */
static bool
xfs_scrub_inode_extent(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	int				whichfork,
	struct fsxattr			*fsx,
	struct getbmapx			*bmap,
	void				*arg)
{
	unsigned long long		*nextoff = arg;
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	unsigned long long		eofs;
	bool				badmap = false;

	if (fsx->fsx_xflags & FS_XFLAG_REALTIME)
		eofs = xctx->geo.rtblocks;
	else
		eofs = xctx->geo.datablocks;
	eofs <<= (xctx->blocklog - BBSHIFT);

	if (bmap->bmv_length == 0) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) has zero length."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length);
	}

	if (bmap->bmv_block >= eofs) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) starts past end of filesystem at %llu."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length, eofs);
	}

	if (bmap->bmv_offset < *nextoff) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) overlaps another extent."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length);
	}

	if (bmap->bmv_block + bmap->bmv_length < bmap->bmv_block ||
	    bmap->bmv_block + bmap->bmv_length >= eofs) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) ends past end of filesystem at %llu."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length, eofs);
	}

	if (bmap->bmv_offset + bmap->bmv_length < bmap->bmv_offset) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) overflows file offset."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length);
	}

	if ((bmap->bmv_oflags & BMV_OF_SHARED) &&
	    (bmap->bmv_oflags & (BMV_OF_PREALLOC | BMV_OF_DELALLOC))) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) has conflicting flags 0x%x."),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length, bmap->bmv_oflags);
	}

	if ((bmap->bmv_oflags & BMV_OF_SHARED) &&
	    !(fsx->fsx_xflags & FS_XFLAG_REFLINK)) {
		badmap = true;
		str_error(ctx, descr,
_("extent (%llu/%llu/%llu) is shared but %s is not?"),
				bmap->bmv_block, bmap->bmv_offset,
				bmap->bmv_length, descr);
	}

	if (!badmap)
		*nextoff = bmap->bmv_offset + bmap->bmv_length;

	return true;
}

/* Scrub an inode's data, xattr, and CoW extent records. */
static bool
xfs_scan_inode_extents(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_bmap_iter		xbi;
	struct getbmapx			key;
	bool				moveon;
	unsigned long long		nextoff;

	xbi.moveon = true;
	xbi.fn = xfs_scrub_inode_extent;
	xbi.arg = &nextoff;
	xbi.descr = descr;

	/* data fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	nextoff = 0;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_DATA_FORK, &key);
	if (!moveon)
		return false;

	/* attr fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	nextoff = 0;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_ATTR_FORK, &key);
	if (!moveon)
		return false;

	if (!(xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_REFLINK))
		return xbi.moveon;

	/* cow fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	nextoff = 0;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_COW_FORK, &key);
	if (!moveon)
		return false;

	return xbi.moveon;
}

enum xfs_xattr_ns {
	RXT_USER	= 0,
	RXT_ROOT	= ATTR_ROOT,
	RXT_TRUST	= ATTR_TRUST,
	RXT_SECURE	= ATTR_SECURE,
	RXT_MAX		= 4,
};

static const enum xfs_xattr_ns known_attr_ns[RXT_MAX] = {
	RXT_USER,
	RXT_ROOT,
	RXT_TRUST,
	RXT_SECURE,
};

/* Read all the extended attributes of a file handle. */
static bool
xfs_read_handle_xattrs(
	struct scrub_ctx	*ctx,
	const char		*descr,
	struct xfs_handle	*handle,
	enum xfs_xattr_ns	ns)
{
	struct attrlist_cursor	cur;
	struct attr_multiop	mop;
	char			attrbuf[XFS_XATTR_LIST_MAX];
	char			*firstname = NULL;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct attrlist		*attrlist = (struct attrlist *)attrbuf;
	struct attrlist_ent	*ent;
	bool			moveon = true;
	int			i;
	int			flags = 0;
	int			error;

	flags |= ns;
	memset(&attrbuf, 0, XFS_XATTR_LIST_MAX);
	memset(&cur, 0, sizeof(cur));
	mop.am_opcode = ATTR_OP_GET;
	mop.am_flags = flags;
	while ((error = attr_list_by_handle(handle, sizeof(*handle),
			attrbuf, XFS_XATTR_LIST_MAX, flags, &cur)) == 0) {
		for (i = 0; i < attrlist->al_count; i++) {
			ent = ATTR_ENTRY(attrlist, i);

			/*
			 * XFS has a longstanding bug where the attr cursor
			 * never gets updated, causing an infinite loop.
			 * Detect this and bail out.
			 */
			if (i == 0 && xctx->checked_xattrs) {
				if (firstname == NULL) {
					firstname = malloc(ent->a_valuelen);
					memcpy(firstname, ent->a_name,
							ent->a_valuelen);
				} else if (memcmp(firstname, ent->a_name,
							ent->a_valuelen) == 0) {
					str_error(ctx, descr,
_("duplicate extended attribute \"%s\", buggy XFS?"),
							ent->a_name);
					moveon = false;
					goto out;
				}
			}

			mop.am_attrname = ent->a_name;
			mop.am_attrvalue = ctx->readbuf;
			mop.am_length = IO_MAX_SIZE;
			error = attr_multi_by_handle(handle, sizeof(*handle),
					&mop, 1, flags);
			if (error)
				goto out;
		}

		if (!attrlist->al_more)
			break;
	}

	/* ATTR_TRUST doesn't currently work on Linux... */
	if (ns == RXT_TRUST && error && errno == EINVAL)
		error = 0;

out:
	if (firstname)
		free(firstname);
	if (error)
		str_errno(ctx, descr);
	return moveon;
}

/* Verify the contents, xattrs, and extent maps of an inode. */
static bool
xfs_scrub_inode(
	struct scrub_ctx	*ctx,
	xfs_agnumber_t		agno,
	struct xfs_handle	*handle,
	struct xfs_bstat	*bstat,
	void			*arg)
{
	struct stat64		fd_sb;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	static char		linkbuf[PATH_MAX];
	char			descr[DESCR_BUFSZ];
	unsigned long long	eofs;
	bool			moveon = true;
	int			fd = -1;
	int			i;
	int			error;

	snprintf(descr, DESCR_BUFSZ, _("inode %llu/%u"), bstat->bs_ino,
			bstat->bs_gen);

	/* Check symlink contents. */
	if (S_ISLNK(bstat->bs_mode)) {
		error = readlink_by_handle(handle, sizeof(*handle), linkbuf,
				PATH_MAX);
		if (error < 0)
			str_errno(ctx, descr);
		return true;
	}

	/* Check block sizes. */
	if (!S_ISBLK(bstat->bs_mode) && !S_ISCHR(bstat->bs_mode) &&
	    bstat->bs_blksize != xctx->geo.blocksize)
		str_error(ctx, descr,
_("Block size mismatch %u, expected %u"),
				bstat->bs_blksize, xctx->geo.blocksize);
	if (bstat->bs_xflags & FS_XFLAG_EXTSIZE) {
		if (bstat->bs_extsize > (MAXEXTLEN << xctx->blocklog))
			str_error(ctx, descr,
_("Extent size hint %u too large"), bstat->bs_extsize);
		if (!(bstat->bs_xflags & FS_XFLAG_REALTIME) &&
		    bstat->bs_extsize > (xctx->geo.agblocks << (xctx->blocklog - 1)))
			str_error(ctx, descr,
_("Extent size hint %u too large for AG"), bstat->bs_extsize);
		if (!(bstat->bs_xflags & FS_XFLAG_REALTIME) &&
		    bstat->bs_extsize % xctx->geo.blocksize)
			str_error(ctx, descr,
_("Extent size hint %u not a multiple of blocksize"), bstat->bs_extsize);
		if ((bstat->bs_xflags & FS_XFLAG_REALTIME) &&
		    bstat->bs_extsize % (xctx->geo.rtextsize << xctx->blocklog))
			str_error(ctx, descr,
_("Extent size hint %u not a multiple of rt extent size"), bstat->bs_extsize);
	}
	if ((bstat->bs_xflags & FS_XFLAG_REFLINK) &&
	    !(xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_REFLINK))
		str_error(ctx, descr,
_("Is a shared inode on a non-reflink filesystem?"), 0);
	if ((bstat->bs_xflags & FS_XFLAG_COWEXTSIZE) &&
	    !(xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_REFLINK))
		str_error(ctx, descr,
_("Has a CoW extent size hint on a non-reflink filesystem?"), 0);
	if (bstat->bs_xflags & FS_XFLAG_COWEXTSIZE) {
		if (bstat->bs_cowextsize > (MAXEXTLEN << xctx->blocklog))
			str_error(ctx, descr,
_("CoW Extent size hint %u too large"), bstat->bs_cowextsize);
		if (bstat->bs_cowextsize > (xctx->geo.agblocks << (xctx->blocklog - 1)))
			str_error(ctx, descr,
_("CoW Extent size hint %u too large for AG"), bstat->bs_cowextsize);
		if (bstat->bs_cowextsize % xctx->geo.blocksize)
			str_error(ctx, descr,
_("CoW Extent size hint %u not a multiple of blocksize"), bstat->bs_cowextsize);
	}
	if (bstat->bs_xflags & FS_XFLAG_REALTIME)
		eofs = xctx->geo.rtblocks;
	else
		eofs = xctx->geo.datablocks;
	if (!(bstat->bs_xflags & FS_XFLAG_REFLINK) && bstat->bs_blocks >= eofs)
		str_error(ctx, descr,
_("Claims having more blocks (%llu) than there are in filesystem (%llu)"),
				bstat->bs_blocks << (xctx->blocklog - BBSHIFT),
				eofs << (xctx->blocklog - BBSHIFT));

	/* Try to open the inode to pin it. */
	if (S_ISREG(bstat->bs_mode) || S_ISDIR(bstat->bs_mode)) {
		fd = open_by_fshandle(handle, sizeof(*handle),
				O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
		if (fd < 0) {
			char buf[DESCR_BUFSZ];

			str_warn(ctx, descr, "%s", strerror_r(errno,
					buf, DESCR_BUFSZ));
			return true;
		}
	}

	/* XXX: Some day, check child -> parent dir -> child. */

	/*
	 * Read all the extended attributes.  If any of the read
	 * functions decline to move on, we can try again with the
	 * VFS functions if we have a file descriptor.
	 */
	moveon = true;
	for (i = 0; i < RXT_MAX; i++) {
		moveon = xfs_read_handle_xattrs(ctx, descr, handle,
				known_attr_ns[i]);
		if (!moveon)
			break;
	}
	if (!moveon && fd >= 0) {
		moveon = generic_scan_xattrs(ctx, descr, fd);
		if (!moveon)
			goto out;
	}
	if (!moveon)
		xctx->checked_xattrs = false;

	/*
	 * The rest of the scans require a file descriptor, so bail out
	 * if we don't have one.
	 */
	if (fd < 0)
		goto out;

	if (xctx->kernel_scrub) {
		/* Scan the extent maps with the kernel scrubber. */
		moveon = xfs_scrub_inode_metadata(ctx, bstat->bs_ino, fd);
		if (!moveon)
			goto out;
	} else if (xctx->bmapx) {
		/* Scan the extent maps with GETBMAPX. */
		moveon = xfs_scan_inode_extents(ctx, descr, fd);
		if (!moveon)
			goto out;
	} else {
		error = fstat64(fd, &fd_sb);
		if (error) {
			str_errno(ctx, descr);
			goto out;
		}

		/* Fall back to the FIEMAP scanner. */
		moveon = generic_scan_extents(ctx, descr, fd, &fd_sb, false);
		if (!moveon)
			goto out;
		moveon = generic_scan_extents(ctx, descr, fd, &fd_sb, true);
		if (!moveon)
			goto out;
	}

	if (S_ISDIR(bstat->bs_mode)) {
		/* XXX: Some day, check dir -> child -> parent(dir) */

		/* Check the directory entries. */
		moveon = generic_check_directory(ctx, descr, &fd);
		if (!moveon)
			goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	return moveon;
}

/* Verify all the inodes in a filesystem. */
static bool
xfs_scan_inodes(
	struct scrub_ctx	*ctx)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	if (!xctx->bulkstat)
		return generic_scan_inodes(ctx);

	xctx->checked_xattrs = true;
	return xfs_scan_all_inodes(ctx, xfs_scrub_inode, NULL);
}

/* Phase 4 */

/* Check an inode's extents. */
static bool
xfs_scan_extents(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	struct stat64		*sb,
	bool			attr_fork)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	/*
	 * If we have bulkstat and either bmap or kernel scrubbing,
	 * we already checked the extents.
	 */
	if (xctx->bulkstat && (xctx->bmapx || xctx->kernel_scrub))
		return true;

	return generic_scan_extents(ctx, descr, fd, sb, attr_fork);
}

/* Try to read all the extended attributes. */
static bool
xfs_scan_xattrs(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	/* If we have bulkstat, we already checked the attributes. */
	if (xctx->bulkstat && xctx->checked_xattrs)
		return true;

	return generic_scan_xattrs(ctx, descr, fd);
}

/* Try to read all the extended attributes of things that have no fd. */
static bool
xfs_scan_special_xattrs(
	struct scrub_ctx	*ctx,
	const char		*path)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	/* If we have bulkstat, we already checked the attributes. */
	if (xctx->bulkstat && xctx->checked_xattrs)
		return true;

	return generic_scan_special_xattrs(ctx, path);
}

/* Traverse the directory tree. */
static bool
xfs_scan_fs_tree(
	struct scrub_ctx	*ctx)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	/* If we have bulkstat, we already checked the attributes. */
	if (xctx->bulkstat && xctx->checked_xattrs)
		return true;

	return generic_scan_fs_tree(ctx);
}

/* Phase 5 */

/* Verify disk blocks with GETFSMAP */

struct xfs_verify_extent {
	/* Maintain state for the lazy read verifier. */
	struct read_verify	rv;

	/* Store bad extents if we don't have parent pointers. */
	struct extent_tree	*d_bad;
	struct extent_tree	*r_bad;

	/* Track the last extent we saw. */
	uint64_t		laststart;
	uint64_t		lastcount;
	bool			lastshared;
};

/* Report an IO error resulting from read-verify based off getfsmap. */
static bool
xfs_check_rmap_error_report(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			idx,
	struct getfsmap		*map,
	void			*arg)
{
	const char		*type;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	char			buf[32];
	uint64_t		err_startblock = *(uint64_t *)arg;
	uint64_t		err_off;

	if (err_startblock > map->fmv_block)
		err_off = err_startblock - map->fmv_block;
	else
		err_off = 0;

	snprintf(buf, 32, _("sector %llu"), map->fmv_block + err_off);

	if (map->fmv_oflags & FMV_OF_SPECIAL_OWNER) {
		type = xfs_decode_special_owner(map->fmv_owner);
		str_error(ctx, buf,
_("%s failed read verification."),
				type);
	} else if (xctx->parent_ptrs) {
		/* XXX: go find the parent path */
		str_error(ctx, buf,
_("XXX: inode %lld offset %llu failed read verification."),
				map->fmv_owner, map->fmv_offset + err_off);
	}
	return true;
}

/* Handle a read error in the rmap-based read verify. */
void
xfs_check_rmap_ioerr(
	struct read_verify_pool	*rvp,
	struct disk		*disk,
	uint64_t		startblock,
	uint64_t		blockcount,
	int			error,
	void			*arg)
{
	struct getfsmap		keys[2];
	struct xfs_fsmap_iter	xfi;
	struct scrub_ctx	*ctx = rvp->rvp_ctx;
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct xfs_verify_extent	*ve;
	struct extent_tree	*tree;
	dev_t			dev;
	bool			moveon;

	ve = arg;
	dev = xfs_disk_to_dev(xctx, disk);

	/*
	 * If we don't have parent pointers, save the bad extent for
	 * later rescanning.
	 */
	if (!xctx->parent_ptrs) {
		if (dev == xctx->fsinfo.fs_datadev)
			tree = ve->d_bad;
		else if (dev == xctx->fsinfo.fs_rtdev)
			tree = ve->r_bad;
		else
			tree = NULL;
		if (tree) {
			moveon = extent_tree_add(tree, startblock, blockcount);
			if (!moveon)
				str_errno(ctx, ctx->mntpoint);
		}
	}

	/* Go figure out which blocks are bad from the fsmap. */
	memset(keys, 0, sizeof(struct getfsmap) * 2);
	keys->fmv_device = dev;
	keys->fmv_block = startblock;
	(keys + 1)->fmv_device = dev;
	(keys + 1)->fmv_block = startblock + blockcount - 1;
	(keys + 1)->fmv_owner = ULLONG_MAX;
	(keys + 1)->fmv_offset = ULLONG_MAX;
	(keys + 1)->fmv_oflags = UINT_MAX;

	xfi.fn = xfs_check_rmap_error_report;
	xfi.arg = &startblock;
	xfi.moveon = true;
	xfs_iterate_fsmap(ctx, &xfi, 0, keys);
}

/* Read verify a (data block) extent. */
static bool
xfs_check_rmap(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				idx,
	struct getfsmap			*map,
	void				*arg)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_verify_extent	*ve;
	struct disk			*disk;
	uint64_t			eofs;
	uint64_t			min_block;
	bool				badflags = false;
	bool				badmap = false;

	ve = ((struct xfs_verify_extent *)arg) + idx;

	dbg_printf("rmap dev %d:%d block %llu owner %lld offset %llu "
			"len %llu flags 0x%x\n", major(map->fmv_device),
			minor(map->fmv_device), map->fmv_block,
			map->fmv_owner, map->fmv_offset,
			map->fmv_length, map->fmv_oflags);

	/* If kernel already checked this... */
	if (xctx->kernel_scrub)
		goto skip_check;

	if (map->fmv_device == xctx->fsinfo.fs_datadev)
		eofs = xctx->geo.datablocks;
	else if (map->fmv_device == xctx->fsinfo.fs_rtdev)
		eofs = xctx->geo.rtblocks;
	else if (map->fmv_device == xctx->fsinfo.fs_logdev)
		eofs = xctx->geo.logblocks;
	else
		assert(0);
	eofs <<= (xctx->blocklog - BBSHIFT);

	/* Don't go past EOFS */
	if (map->fmv_block >= eofs) {
		badmap = true;
		str_error(ctx, descr,
_("rmap (%llu/%llu/%llu) starts past end of filesystem at %llu."),
				map->fmv_block, map->fmv_offset,
				map->fmv_length, eofs);
	}

	if (map->fmv_block + map->fmv_length < map->fmv_block ||
	    map->fmv_block + map->fmv_length >= eofs) {
		badmap = true;
		str_error(ctx, descr,
_("rmap (%llu/%llu/%llu) ends past end of filesystem at %llu."),
				map->fmv_block, map->fmv_offset,
				map->fmv_length, eofs);
	}

	/* Check for illegal overlapping. */
	if (ve->lastshared && (map->fmv_oflags & FMV_OF_SHARED))
		min_block = ve->laststart;
	else
		min_block = map->fmv_block < ve->laststart + ve->lastcount;

	if (map->fmv_block < min_block) {
		badmap = true;
		str_error(ctx, descr,
_("rmap (%llu/%llu/%llu) overlaps another rmap."),
				map->fmv_block, map->fmv_offset,
				map->fmv_length);
	}

	/* can't have shared on non-reflink */
	if ((map->fmv_oflags & FMV_OF_SHARED) &&
	    !(xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_REFLINK))
		badflags = true;

	/* unwritten can't have any of the other flags */
	if ((map->fmv_oflags & FMV_OF_PREALLOC) &&
	     (map->fmv_oflags & (FMV_OF_ATTR_FORK | FMV_OF_EXTENT_MAP |
				 FMV_OF_SHARED | FMV_OF_SPECIAL_OWNER)))
		badflags = true;

	/* attr fork can't be shared or uwnritten or special */
	if ((map->fmv_oflags & FMV_OF_ATTR_FORK) &&
	     (map->fmv_oflags & (FMV_OF_PREALLOC | FMV_OF_SHARED |
				 FMV_OF_SPECIAL_OWNER)))
		badflags = true;

	/* extent maps can only have attrfork */
	if ((map->fmv_oflags & FMV_OF_EXTENT_MAP) &&
	     (map->fmv_oflags & (FMV_OF_PREALLOC | FMV_OF_SHARED |
				 FMV_OF_SPECIAL_OWNER)))
		badflags = true;

	/* shared maps can't have any of the other flags */
	if ((map->fmv_oflags & FMV_OF_SHARED) &&
	     (map->fmv_oflags & (FMV_OF_PREALLOC | FMV_OF_ATTR_FORK |
				 FMV_OF_EXTENT_MAP | FMV_OF_SPECIAL_OWNER)))

	/* special owners can't have any of the other flags */
	if ((map->fmv_oflags & FMV_OF_SPECIAL_OWNER) &&
	     (map->fmv_oflags & (FMV_OF_PREALLOC | FMV_OF_ATTR_FORK |
				 FMV_OF_EXTENT_MAP | FMV_OF_SHARED)))
		badflags = true;

	if (badflags) {
		badmap = true;
		str_error(ctx, descr,
_("rmap (%llu/%llu/%llu) has conflicting flags 0x%x."),
				map->fmv_block, map->fmv_offset,
				map->fmv_length, map->fmv_oflags);
	}

	/* If this rmap is suspect, don't bother verifying it. */
	if (badmap)
		goto out;

skip_check:
	/* Remember this extent. */
	ve->lastshared = (map->fmv_oflags & FMV_OF_SHARED);
	ve->laststart = map->fmv_block;
	ve->lastcount = map->fmv_length;

	/* "Unknown" extents should be verified; they could be data. */
	if ((map->fmv_oflags & FMV_OF_SPECIAL_OWNER) &&
			map->fmv_owner == FMV_OWN_UNKNOWN)
		map->fmv_oflags &= ~FMV_OF_SPECIAL_OWNER;

	/*
	 * We only care about read-verifying data extents that have been
	 * written to disk.  This means we can skip "special" owners
	 * (metadata), xattr blocks, unwritten extents, and extent maps.
	 * These should all get checked elsewhere in the scrubber.
	 */
	if (map->fmv_oflags & (FMV_OF_PREALLOC | FMV_OF_ATTR_FORK |
			       FMV_OF_EXTENT_MAP | FMV_OF_SPECIAL_OWNER))
		goto out;

	/* XXX: Filter out directory data blocks. */

	/* Schedule the read verify command for (eventual) running. */
	disk = xfs_dev_to_disk(xctx, map->fmv_device);

	read_verify_schedule(&xctx->rvp, &ve->rv, disk, map->fmv_block,
			map->fmv_length, ve);

out:
	/* Is this the last extent?  Fire off the read. */
	if (map->fmv_oflags & FMV_OF_LAST)
		read_verify_force(&xctx->rvp, &ve->rv);

	return true;
}

/* Verify all the blocks in a filesystem. */
static bool
xfs_scan_rmaps(
	struct scrub_ctx		*ctx)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct extent_tree		d_bad;
	struct extent_tree		r_bad;
	struct xfs_verify_extent	*ve;
	struct xfs_verify_extent	*v;
	int				i;
	bool				moveon;

	/*
	 * Initialize our per-thread context.  By convention,
	 * the log device comes first, then the rt device, and then
	 * the AGs.
	 */
	ve = calloc(xctx->geo.agcount + 2, sizeof(struct xfs_verify_extent));
	if (!ve) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	moveon = extent_tree_init(&d_bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_ve;
	}

	moveon = extent_tree_init(&r_bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_dbad;
	}

	for (i = 0, v = ve; i < xctx->geo.agcount + 2; i++, v++) {
		v->d_bad = &d_bad;
		v->r_bad = &r_bad;
	}

	read_verify_pool_init(&xctx->rvp, ctx, ctx->readbuf, IO_MAX_SIZE,
			xctx->geo.blocksize, xfs_check_rmap_ioerr, NULL,
			scrub_nproc(ctx));
	moveon = xfs_scan_all_blocks(ctx, xfs_check_rmap, ve + 2);
	if (!moveon)
		goto out_pool;

	for (i = 0, v = ve; i < xctx->geo.agcount + 2; i++, v++)
		read_verify_force(&xctx->rvp, &v->rv);
	read_verify_pool_destroy(&xctx->rvp);

	/* Scan the whole dir tree to see what matches the bad extents. */
	if (!extent_tree_empty(&d_bad) || !extent_tree_empty(&r_bad))
		moveon = xfs_report_verify_errors(ctx, &d_bad, &r_bad);

	extent_tree_free(&r_bad);
	extent_tree_free(&d_bad);
	free(ve);
	return moveon;

out_pool:
	read_verify_pool_destroy(&xctx->rvp);
	extent_tree_free(&r_bad);
out_dbad:
	extent_tree_free(&d_bad);
out_ve:
	free(ve);
	return moveon;
}

/* Read-verify with BULKSTAT + GETBMAPX */
struct xfs_verify_inode {
	struct extent_tree		d_good;
	struct extent_tree		r_good;
	struct extent_tree		*d_bad;
	struct extent_tree		*r_bad;
};

struct xfs_verify_submit {
	struct read_verify_pool		*rvp;
	struct extent_tree		*bad;
	struct disk			*disk;
	struct read_verify		rv;
};

/* Finish a inode block scan. */
void
xfs_verify_inode_bmap_ioerr(
	struct read_verify_pool		*rvp,
	struct disk			*disk,
	uint64_t			startblock,
	uint64_t			blockcount,
	int				error,
	void				*arg)
{
	struct extent_tree		*tree = arg;

	extent_tree_add(tree, startblock, blockcount);
}

/* Scrub an inode extent and read-verify it. */
bool
xfs_verify_inode_bmap(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	int				whichfork,
	struct fsxattr			*fsx,
	struct getbmapx			*bmap,
	void				*arg)
{
	struct extent_tree		*tree = arg;

	/*
	 * Only do data scrubbing if the extent is neither unwritten nor
	 * delalloc.
	 */
	if (bmap->bmv_oflags & (BMV_OF_PREALLOC | BMV_OF_DELALLOC))
		return true;

	return extent_tree_add(tree, bmap->bmv_block, bmap->bmv_length);
}

/* Read-verify the data blocks of a file via BMAP. */
static bool
xfs_verify_inode(
	struct scrub_ctx		*ctx,
	xfs_agnumber_t			agno,
	struct xfs_handle		*handle,
	struct xfs_bstat		*bstat,
	void				*arg)
{
	struct stat64			fd_sb;
	struct xfs_bmap_iter		xbi;
	struct getbmapx			key;
	struct xfs_verify_inode		*vi;
	char				descr[DESCR_BUFSZ];
	bool				moveon = true;
	int				fd = -1;
	int				error;

	if (!S_ISREG(bstat->bs_mode))
		return true;

	snprintf(descr, DESCR_BUFSZ, _("inode %llu/%u"), bstat->bs_ino,
			bstat->bs_gen);

	/* Try to open the inode to pin it. */
	fd = open_by_fshandle(handle, sizeof(*handle),
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0) {
		char buf[DESCR_BUFSZ];

		str_warn(ctx, descr, "%s", strerror_r(errno,
				buf, DESCR_BUFSZ));
		return true;
	}

	if (arg) {
		/* Use BMAPX */
		vi = ((struct xfs_verify_inode *)arg) + agno;

		xbi.moveon = true;
		xbi.fn = xfs_verify_inode_bmap;
		xbi.descr = descr;
		if (bstat->bs_xflags & FS_XFLAG_REALTIME)
			xbi.arg = &vi->r_good;
		else
			xbi.arg = &vi->d_good;

		/* data fork */
		memset(&key, 0, sizeof(key));
		key.bmv_length = ULLONG_MAX;
		moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_DATA_FORK, &key);
		if (!moveon)
			goto out;
		moveon = xbi.moveon;
	} else {
		error = fstat64(fd, &fd_sb);
		if (error) {
			str_errno(ctx, descr);
			goto out;
		}

		/* Use generic_file_read */
		moveon = generic_read_file(ctx, descr, fd, &fd_sb);
	}

out:
	if (fd >= 0)
		close(fd);
	return moveon;
}

static bool
xfs_schedule_read_verify(
	uint64_t			start,
	uint64_t			length,
	void				*arg)
{
	struct xfs_verify_submit	*rvs = arg;

	read_verify_schedule(rvs->rvp, &rvs->rv, rvs->disk, start, length,
			rvs->bad);
	return true;
}

/* Verify all the file data in a filesystem. */
static bool
xfs_verify_inodes(
	struct scrub_ctx	*ctx)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;
	struct extent_tree	d_good;
	struct extent_tree	d_bad;
	struct extent_tree	r_good;
	struct extent_tree	r_bad;
	struct xfs_verify_inode	*vi;
	struct xfs_verify_inode	*v;
	struct xfs_verify_submit	vs;
	int			i;
	bool			moveon;

	vi = calloc(xctx->geo.agcount, sizeof(struct xfs_verify_inode));
	if (!vi) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	moveon = extent_tree_init(&d_good);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_vi;
	}

	moveon = extent_tree_init(&d_bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_dgood;
	}

	moveon = extent_tree_init(&r_good);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_dbad;
	}

	moveon = extent_tree_init(&r_bad);
	if (!moveon) {
		str_errno(ctx, ctx->mntpoint);
		goto out_rgood;
	}

	for (i = 0, v = vi; i < xctx->geo.agcount; i++, v++) {
		v->d_bad = &d_bad;
		v->r_bad = &r_bad;

		moveon = extent_tree_init(&v->d_good);
		if (!moveon) {
			str_errno(ctx, ctx->mntpoint);
			goto out_varray;
		}

		moveon = extent_tree_init(&v->r_good);
		if (!moveon) {
			str_errno(ctx, ctx->mntpoint);
			goto out_varray;
		}
	}

	/* Scan all the inodes for extent information. */
	moveon = xfs_scan_all_inodes(ctx, xfs_verify_inode, vi);
	if (!moveon)
		goto out_varray;

	/* Merge all the IOs. */
	for (i = 0, v = vi; i < xctx->geo.agcount; i++, v++) {
		extent_tree_merge(&d_good, &v->d_good);
		extent_tree_free(&v->d_good);
		extent_tree_merge(&r_good, &v->r_good);
		extent_tree_free(&v->r_good);
	}

	/* Run all the IO in batches. */
	memset(&vs, 0, sizeof(struct xfs_verify_submit));
	vs.rvp = &xctx->rvp;
	read_verify_pool_init(&xctx->rvp, ctx, ctx->readbuf, IO_MAX_SIZE,
			xctx->geo.blocksize, xfs_verify_inode_bmap_ioerr,
			NULL, scrub_nproc(ctx));
	vs.disk = &xctx->datadev;
	vs.bad = &d_bad;
	moveon = extent_tree_iterate(&d_good, xfs_schedule_read_verify, &vs);
	if (!moveon)
		goto out_pool;
	vs.disk = &xctx->rtdev;
	vs.bad = &r_bad;
	moveon = extent_tree_iterate(&r_good, xfs_schedule_read_verify, &vs);
	if (!moveon)
		goto out_pool;
	read_verify_force(&xctx->rvp, &vs.rv);
	read_verify_pool_destroy(&xctx->rvp);

	/* Re-scan the file bmaps to see if they match the bad. */
	if (!extent_tree_empty(&d_bad) || !extent_tree_empty(&r_bad))
		moveon = xfs_report_verify_errors(ctx, &d_bad, &r_bad);

	goto out_varray;

out_pool:
	read_verify_pool_destroy(&xctx->rvp);
out_varray:
	for (i = 0, v = vi; i < xctx->geo.agcount; i++, v++) {
		extent_tree_free(&v->d_good);
		extent_tree_free(&v->r_good);
	}
	extent_tree_free(&r_bad);
out_rgood:
	extent_tree_free(&r_good);
out_dbad:
	extent_tree_free(&d_bad);
out_dgood:
	extent_tree_free(&d_good);
out_vi:
	free(vi);
	return moveon;
}

/* Verify all the file data in a filesystem with the generic verifier. */
static bool
xfs_verify_inodes_generic(
	struct scrub_ctx	*ctx)
{
	return xfs_scan_all_inodes(ctx, xfs_verify_inode, NULL);
}

/* Scan all the blocks in a filesystem. */
static bool
xfs_scan_blocks(
	struct scrub_ctx		*ctx)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;

	switch (xctx->data_scrubber) {
	case DS_NOSCRUB:
		return true;
	case DS_READ:
		return generic_scan_blocks(ctx);
	case DS_BULKSTAT_READ:
		return xfs_verify_inodes_generic(ctx);
	case DS_BMAPX:
		return xfs_verify_inodes(ctx);
	case DS_FSMAP:
		return xfs_scan_rmaps(ctx);
	default:
		assert(0);
	}
}

/* Read an entire file's data. */
static bool
xfs_read_file(
	struct scrub_ctx	*ctx,
	const char		*descr,
	int			fd,
	struct stat64		*sb)
{
	struct xfs_scrub_ctx	*xctx = ctx->priv;

	if (xctx->data_scrubber != DS_READ)
		return true;

	return generic_read_file(ctx, descr, fd, sb);
}

/* Phase 6 */

struct xfs_summary_counts {
	unsigned long long	inodes;		/* number of inodes */
	unsigned long long	dblocks;	/* data dev fsblocks */
	unsigned long long	rblocks;	/* rt dev fsblocks */
	unsigned long long	next_dsect;	/* next fs sector we see? */
	unsigned long long	ag_owner;	/* freespace blocks */
	struct extent_tree	dext;		/* data extent bitmap */
	struct extent_tree	rext;		/* rt extent bitmap */
};

struct xfs_inode_fork_summary {
	struct extent_tree	*tree;
	unsigned long long	blocks;
};

/* Record data block extents in a bitmap. */
bool
xfs_record_inode_summary_bmap(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				fd,
	int				whichfork,
	struct fsxattr			*fsx,
	struct getbmapx			*bmap,
	void				*arg)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_inode_fork_summary	*ifs = arg;
	int				shift;

	shift = (xctx->blocklog - BBSHIFT);
	extent_tree_add(ifs->tree, bmap->bmv_block >> shift,
			bmap->bmv_length >> shift);
	ifs->blocks += bmap->bmv_length >> shift;
	return true;
}

/* Record inode and block usage. */
static bool
xfs_record_inode_summary(
	struct scrub_ctx		*ctx,
	xfs_agnumber_t			agno,
	struct xfs_handle		*handle,
	struct xfs_bstat		*bstat,
	void				*arg)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_summary_counts	*counts;
	struct xfs_bmap_iter		xbi;
	struct getbmapx			key;
	struct xfs_inode_fork_summary	ifs;
	unsigned long long		rtblocks;
	char				descr[DESCR_BUFSZ];
	int				fd;
	bool				moveon;

	counts = ((struct xfs_summary_counts *)arg) + agno;
	counts->inodes++;
	if (xctx->fsmap || bstat->bs_blocks == 0)
		return true;

	if (!S_ISREG(bstat->bs_mode)) {
		counts->dblocks += bstat->bs_blocks;
		return true;
	}

	/* Potentially a reflinked file, so collect the bitmap... */
	snprintf(descr, DESCR_BUFSZ, _("inode %llu/%u"), bstat->bs_ino,
			bstat->bs_gen);

	/* Try to open the inode to pin it. */
	fd = open_by_fshandle(handle, sizeof(*handle),
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0) {
		char buf[DESCR_BUFSZ];

		str_warn(ctx, descr, "%s", strerror_r(errno,
				buf, DESCR_BUFSZ));
		return true;
	}

	xbi.moveon = true;
	xbi.arg = &ifs;
	xbi.fn = xfs_record_inode_summary_bmap;
	xbi.descr = descr;

	/* data fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	if (bstat->bs_xflags & FS_XFLAG_REALTIME)
		ifs.tree = &counts->rext;
	else
		ifs.tree = &counts->dext;
	ifs.blocks = 0;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_DATA_FORK, &key);
	if (!moveon)
		goto out;
	moveon = xbi.moveon;
	rtblocks = (bstat->bs_xflags & FS_XFLAG_REALTIME) ? ifs.blocks : 0;

	/* attr fork */
	memset(&key, 0, sizeof(key));
	key.bmv_length = ULLONG_MAX;
	ifs.tree = &counts->dext;
	moveon = xfs_iterate_bmap(ctx, &xbi, fd, XFS_ATTR_FORK, &key);
	if (!moveon)
		goto out;
	moveon = xbi.moveon;

	counts->dblocks += bstat->bs_blocks - rtblocks;
	counts->rblocks += rtblocks;

out:
	if (fd >= 0)
		close(fd);
	return moveon;
}

/* Record block usage. */
static bool
xfs_record_block_summary(
	struct scrub_ctx		*ctx,
	const char			*descr,
	int				idx,
	struct getfsmap			*fsmap,
	void				*arg)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_summary_counts	*counts;
	unsigned long long		len;
	int				shift;

	if (idx < -1)
		return true;
	if ((fsmap->fmv_oflags & FMV_OF_SPECIAL_OWNER) &&
	    fsmap->fmv_owner == FMV_OWN_FREE)
		return true;

	counts = ((struct xfs_summary_counts *)arg) + idx;
	len = fsmap->fmv_length;
	shift = xctx->blocklog - BBSHIFT;

	/* freesp btrees live in free space, need to adjust counters later. */
	if ((fsmap->fmv_oflags & FMV_OF_SPECIAL_OWNER) &&
	    fsmap->fmv_owner == FMV_OWN_AG) {
		counts->ag_owner += fsmap->fmv_length >> shift;
	}
	if (idx == -1) {
		/* Count realtime extents. */
		counts->rblocks += fsmap->fmv_length >> shift;
	} else {
		/* Count data extents. */
		if (counts->next_dsect >= fsmap->fmv_block + fsmap->fmv_length)
			return true;
		else if (counts->next_dsect > fsmap->fmv_block)
			len -= counts->next_dsect - fsmap->fmv_block;
			
		counts->dblocks += len >> shift;
		counts->next_dsect = fsmap->fmv_block + fsmap->fmv_length;
	}

	return true;
}

/* Sum the blocks in each extent. */
static bool
xfs_summary_count_helper(
	uint64_t			start,
	uint64_t			length,
	void				*arg)
{
	unsigned long long		*count = arg;

	*count += length;
	return true;
}

/* Count all inodes and blocks in the filesystem, compare to superblock. */
static bool
xfs_check_summary(
	struct scrub_ctx		*ctx)
{
	struct xfs_scrub_ctx		*xctx = ctx->priv;
	struct xfs_fsop_counts		fc;
	struct xfs_fsop_resblks		rb;
	struct xfs_fsop_ag_resblks	arb;
	struct statvfs			sfs;
	struct xfs_summary_counts	*summary;
	unsigned long long		fd;
	unsigned long long		fr;
	unsigned long long		fi;
	unsigned long long		sd;
	unsigned long long		sr;
	unsigned long long		si;
	unsigned long long		absdiff;
	xfs_agnumber_t			agno;
	bool				moveon;
	bool				complain;
	int				shift;
	int				error;

	if (!xctx->bulkstat)
		return generic_check_summary(ctx);

	summary = calloc(xctx->geo.agcount + 2,
			sizeof(struct xfs_summary_counts));
	if (!summary) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	/* Flush everything out to disk before we start counting. */
	error = syncfs(ctx->mnt_fd);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	if (xctx->fsmap) {
		/* Use fsmap to count blocks. */
		moveon = xfs_scan_all_blocks(ctx, xfs_record_block_summary,
				summary + 2);
		if (!moveon)
			goto out;
	} else {
		/* Reflink w/o rmap; have to collect extents in a bitmap. */
		for (agno = 0; agno < xctx->geo.agcount + 2; agno++) {
			moveon = extent_tree_init(&summary[agno].dext);
			if (!moveon) {
				str_errno(ctx, ctx->mntpoint);
				goto out;
			}
			moveon = extent_tree_init(&summary[agno].rext);
			if (!moveon) {
				str_errno(ctx, ctx->mntpoint);
				goto out;
			}
		}
	}

	/* Scan the whole fs. */
	moveon = xfs_scan_all_inodes(ctx, xfs_record_inode_summary, summary);
	if (!moveon)
		goto out;

	if (!xctx->fsmap && (xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_REFLINK)) {
		/* Reflink w/o rmap; merge the bitmaps. */
		for (agno = 1; agno < xctx->geo.agcount + 2; agno++) {
			extent_tree_merge(&summary[0].dext, &summary[agno].dext);
			extent_tree_free(&summary[agno].dext);
			extent_tree_merge(&summary[0].rext, &summary[agno].rext);
			extent_tree_free(&summary[agno].rext);
		}
		moveon = extent_tree_iterate(&summary[0].dext,
				xfs_summary_count_helper, &summary[0].dblocks);
		moveon = extent_tree_iterate(&summary[0].rext,
				xfs_summary_count_helper, &summary[0].rblocks);
		if (!moveon)
			goto out;
	}

	/* Sum the counts. */
	for (agno = 1; agno < xctx->geo.agcount + 2; agno++) {
		summary[0].inodes += summary[agno].inodes;
		summary[0].dblocks += summary[agno].dblocks;
		summary[0].rblocks += summary[agno].rblocks;
		summary[0].ag_owner += summary[agno].ag_owner;
	}

	/* Account for an internal log, if present. */
	if (!xctx->fsmap && xctx->fsinfo.fs_log == NULL)
		summary[0].dblocks += xctx->geo.logblocks;

	/* Account for hidden rt metadata inodes. */
	summary[0].inodes += 2;
	if ((xctx->geo.flags & XFS_FSOP_GEOM_FLAGS_RMAPBT) &&
			xctx->geo.rtblocks > 0)
		summary[0].inodes++;

	/* Fetch the filesystem counters. */
	error = xfsctl(NULL, ctx->mnt_fd, XFS_IOC_FSCOUNTS, &fc);
	if (error)
		str_errno(ctx, ctx->mntpoint);

	/* Grab the fstatvfs counters, since it has to report accurately. */
	error = fstatvfs(ctx->mnt_fd, &sfs);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}

	/*
	 * XFS reserves some blocks to prevent hard ENOSPC, so add those
	 * blocks back to the free data counts.
	 */
	error = xfsctl(NULL, ctx->mnt_fd, XFS_IOC_GET_RESBLKS, &rb);
	if (error)
		str_errno(ctx, ctx->mntpoint);
	sfs.f_bfree += rb.resblks_avail;

	/*
	 * XFS with rmap or reflink reserves blocks in each AG to
	 * prevent the AG from running out of space for metadata blocks.
	 * Add those back to the free data counts.
	 */
	memset(&arb, 0, sizeof(arb));
	error = xfsctl(NULL, ctx->mnt_fd, XFS_IOC_GET_AG_RESBLKS, &arb);
	if (error && errno != ENOTTY)
		str_errno(ctx, ctx->mntpoint);
	sfs.f_bfree += arb.resblks;

	/*
	 * If we counted blocks with fsmap, then dblocks includes
	 * blocks for the AGFL and the freespace/rmap btrees.  The
	 * filesystem treats them as "free", but since we scanned
	 * them, we'll consider them used.
	 */
	sfs.f_bfree -= summary[0].ag_owner;

	/* Report on what we found. */
	shift = xctx->blocklog - (BBSHIFT + 1);
	fd = (xctx->geo.datablocks - sfs.f_bfree) << shift;
	fr = (xctx->geo.rtblocks - fc.freertx) << shift;
	fi = sfs.f_files - sfs.f_ffree;
	sd = summary[0].dblocks << shift;
	sr = summary[0].rblocks << shift;
	si = summary[0].inodes;

	/*
	 * Complain if the counts are off by more than 10% unless
	 * the inaccuracy is less than 32MB worth of blocks or 100 inodes.
	 */
	absdiff = 1 << (25 - xctx->blocklog);
	complain = !within_range(ctx, sd, fd, absdiff, 1, 10, _("data blocks"));
	complain |= !within_range(ctx, sr, fr, absdiff, 1, 10, _("realtime blocks"));
	complain |= !within_range(ctx, si, fi, 100, 1, 10, _("inodes"));

	if (complain || verbose) {
		double		d, r, i;
		char		*du, *ru, *iu;

		if (fr || sr) {
			d = auto_space_units(fd, &du);
			r = auto_space_units(fr, &ru);
			i = auto_units(fi, &iu);
			printf(
_("%.1f%s data blocks used;  %.1f%s rt blocks used;  %.2f%s inodes used.\n"),
					d, du, r, ru, i, iu);
			d = auto_space_units(sd, &du);
			r = auto_space_units(sr, &ru);
			i = auto_units(si, &iu);
			printf(
_("%.1f%s data blocks found; %.1f%s rt blocks found; %.2f%s inodes found.\n"),
					d, du, r, ru, i, iu);
		} else {
			d = auto_space_units(fd, &du);
			i = auto_units(fi, &iu);
			printf(
_("%.1f%s data blocks used;  %.1f%s inodes used.\n"),
					d, du, i, iu);
			d = auto_space_units(sd, &du);
			i = auto_units(si, &iu);
			printf(
_("%.1f%s data blocks found; %.1f%s inodes found.\n"),
					d, du, i, iu);
		}
	}
	moveon = true;

out:
	for (agno = 1; agno < xctx->geo.agcount + 2; agno++) {
		extent_tree_free(&summary[agno].dext);
		extent_tree_free(&summary[agno].rext);
	}
	free(summary);
	return moveon;
}

struct scrub_ops xfs_scrub_ops = {
	.name			= "xfs",
	.cleanup		= xfs_cleanup,
	.scan_fs		= xfs_scan_fs,
	.scan_inodes		= xfs_scan_inodes,
	.check_dir		= generic_check_dir,
	.check_inode		= generic_check_inode,
	.scan_extents		= xfs_scan_extents,
	.scan_xattrs		= xfs_scan_xattrs,
	.scan_special_xattrs	= xfs_scan_special_xattrs,
	.scan_metadata		= xfs_scan_metadata,
	.check_summary		= xfs_check_summary,
	.scan_blocks		= xfs_scan_blocks,
	.read_file		= xfs_read_file,
	.scan_fs_tree		= xfs_scan_fs_tree,
};
