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
#include "disk.h"
#include "scrub.h"
#include "../repair/threads.h"
#include "handle.h"
#include "path.h"

#include "xfs_ioctl.h"

#define BSTATBUF_NR		1024
#define FSMAP_NR		65536
#define BMAP_NR			2048

/* Iterate a range of inodes. */
bool
xfs_iterate_inodes(
	struct scrub_ctx	*ctx,
	struct xfs_inode_iter	*is,
	xfs_agnumber_t		agno,
	void			*fshandle,
	uint64_t		first_ino,
	uint64_t		last_ino)
{
	struct xfs_fsop_bulkreq	bulkreq;
	struct xfs_bstat	*bstatbuf;
	struct xfs_bstat	*p;
	struct xfs_bstat	*endp;
	struct xfs_handle	handle;
	__s32			buflenout = 0;
	bool			moveon = true;
	int			error;

	assert(!debug || !getenv("XFS_SCRUB_NO_BULKSTAT"));

	bstatbuf = calloc(BSTATBUF_NR, sizeof(struct xfs_bstat));
	if (!bstatbuf)
		return false;

	memset(&bulkreq, 0, sizeof(bulkreq));
	bulkreq.lastip = (__u64 *)&first_ino;
	bulkreq.icount  = BSTATBUF_NR;
	bulkreq.ubuffer = (void *)bstatbuf;
	bulkreq.ocount  = &buflenout;

	memcpy(&handle.ha_fsid, fshandle, sizeof(handle.ha_fsid));
	handle.ha_fid.fid_len = sizeof(xfs_fid_t) -
			sizeof(handle.ha_fid.fid_len);
	handle.ha_fid.fid_pad = 0;
	while ((error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_FSBULKSTAT,
			&bulkreq)) == 0) {
		if (buflenout == 0)
			break;
		for (p = bstatbuf, endp = bstatbuf + buflenout; p < endp; p++) {
			if (p->bs_ino > last_ino)
				goto out;

			handle.ha_fid.fid_gen = p->bs_gen;
			handle.ha_fid.fid_ino = p->bs_ino;
			moveon = is->fn(ctx, agno, &handle, p, is->arg);
			if (!moveon)
				goto out;
		}
	}

	if (error) {
		str_errno(ctx, ctx->mntpoint);
		moveon = false;
	}
out:
	free(bstatbuf);
	return moveon;
}

/* Does the kernel support bulkstat? */
bool
xfs_can_iterate_inodes(
	struct scrub_ctx	*ctx)
{
	struct xfs_fsop_bulkreq	bulkreq;
	__u64			lastino;
	__s32			buflenout = 0;
	int			error;

	if (debug && getenv("XFS_SCRUB_NO_BULKSTAT"))
		return false;

	lastino = 0;
	memset(&bulkreq, 0, sizeof(bulkreq));
	bulkreq.lastip = (__u64 *)&lastino;
	bulkreq.icount  = 0;
	bulkreq.ubuffer = NULL;
	bulkreq.ocount  = &buflenout;

	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_FSBULKSTAT,
			&bulkreq);
	return error == -1 && errno == EINVAL;
}

/* Iterate all the extent block mappings between the two keys. */
bool
xfs_iterate_bmap(
	struct scrub_ctx	*ctx,
	struct xfs_bmap_iter	*xbi,
	int			fd,
	int			whichfork,
	struct getbmapx		*key)
{
	struct fsxattr		fsx;
	struct getbmapx		*map;
	struct getbmapx		*p;
	char			descr[DESCR_BUFSZ];
	bool			moveon = true;
	xfs_off_t		new_off;
	int			getxattr_type;
	int			i;
	int			error;

	assert (!debug || !getenv("XFS_SCRUB_NO_BMAP"));

	switch (whichfork) {
	case XFS_ATTR_FORK:
		snprintf(descr, DESCR_BUFSZ, _("%s attr"), xbi->descr);
		break;
	case XFS_COW_FORK:
		snprintf(descr, DESCR_BUFSZ, _("%s CoW"), xbi->descr);
		break;
	case XFS_DATA_FORK:
		snprintf(descr, DESCR_BUFSZ, _("%s data"), xbi->descr);
		break;
	default:
		assert(0);
	}

	map = calloc(BMAP_NR, sizeof(struct getbmapx));
	if (!map) {
		str_errno(ctx, descr);
		return false;
	}

	memcpy(map, key, sizeof(struct getbmapx));
	map->bmv_count = BMAP_NR;

	map->bmv_iflags = BMV_IF_NO_DMAPI_READ | BMV_IF_PREALLOC |
			  BMV_OF_DELALLOC | BMV_IF_NO_HOLES;
	switch (whichfork) {
	case XFS_ATTR_FORK:
		getxattr_type = XFS_IOC_FSGETXATTRA;
		map->bmv_iflags |= BMV_IF_ATTRFORK;
		break;
	case XFS_COW_FORK:
		map->bmv_iflags |= BMV_IF_COWFORK;
		getxattr_type = XFS_IOC_FSGETXATTR;
		break;
	case XFS_DATA_FORK:
		getxattr_type = XFS_IOC_FSGETXATTR;
		break;
	default:
		assert(0);
	}

	error = xfsctl("", fd, getxattr_type, &fsx);
	if (error < 0) {
		str_errno(ctx, descr);
		moveon = false;
		goto out;
	}

	while ((error = xfsctl(descr, fd, XFS_IOC_GETBMAPX, map)) == 0) {

		for (i = 0, p = &map[i + 1]; i < map->bmv_entries; i++, p++) {
			moveon = xbi->fn(ctx, descr, fd, whichfork, &fsx,
					p, xbi->arg);
			if (!moveon)
				goto out;
		}

		if (map->bmv_entries == 0)
			break;
		p = map + map->bmv_entries;
		if (p->bmv_oflags & BMV_OF_LAST)
			break;

		new_off = p->bmv_offset + p->bmv_length;
		map->bmv_length -= new_off - map->bmv_offset;
		map->bmv_offset = new_off;
	}

	/* Pre-reflink filesystems don't know about CoW forks. */
	if (whichfork == XFS_COW_FORK && error && errno == EINVAL)
		error = 0;

	if (error)
		str_errno(ctx, descr);
out:
	memcpy(key, map, sizeof(struct getbmapx));
	free(map);
	return moveon;
}

/* Does the kernel support getbmapx? */
bool
xfs_can_iterate_bmap(
	struct scrub_ctx	*ctx)
{
	struct getbmapx		bsm[2];
	int			error;

	if (debug && getenv("XFS_SCRUB_NO_BMAP"))
		return false;

	memset(bsm, 0, sizeof(struct getbmapx));
	bsm->bmv_length = ULLONG_MAX;
	bsm->bmv_count = 2;
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_GETBMAPX, bsm);
	return error == 0;
}

/* Iterate all the fs block mappings between the two keys. */
bool
xfs_iterate_fsmap(
	struct scrub_ctx	*ctx,
	struct xfs_fsmap_iter	*xfi,
	int			idx,
	struct getfsmap		*keys)
{
	struct getfsmap		*map;
	struct getfsmap		*p;
	char			descr[DESCR_BUFSZ];
	bool			moveon = true;
	int			i;
	int			error;

	assert(!debug || !getenv("XFS_SCRUB_NO_FSMAP"));

	if (idx >= 0)
		snprintf(descr, DESCR_BUFSZ, _("dev %d:%d AG %u fsmap"),
				major(keys->fmv_device),
				minor(keys->fmv_device),
				idx);
	else
		snprintf(descr, DESCR_BUFSZ, _("dev %d:%d fsmap"),
				major(keys->fmv_device),
				minor(keys->fmv_device));

	map = calloc(FSMAP_NR, sizeof(struct getfsmap));
	if (!map) {
		str_errno(ctx, descr);
		return false;
	}

	memcpy(map, keys, sizeof(struct getfsmap) * 2);
	map->fmv_count = FSMAP_NR;

	while ((error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_GETFSMAP,
				map)) == 0) {

		for (i = 0, p = &map[i + 2]; i < map->fmv_entries; i++, p++) {
			moveon = xfi->fn(ctx, descr, idx, p, xfi->arg);
			if (!moveon)
				goto out;
		}

		if (map->fmv_entries == 0)
			break;
		p = map + 1 + map->fmv_entries;
		if (p->fmv_oflags & FMV_OF_LAST)
			break;

		map->fmv_device = p->fmv_device;
		map->fmv_block = p->fmv_block;
		map->fmv_owner = p->fmv_owner;
		map->fmv_offset = p->fmv_offset;
		map->fmv_oflags = p->fmv_oflags;
		map->fmv_length = p->fmv_length;
	}

	if (error) {
		str_errno(ctx, descr);
		moveon = false;
	}
out:
	memcpy(keys, map, sizeof(struct getfsmap) * 2);
	free(map);
	return moveon;
}

/* Does the kernel support getfsmap? */
bool
xfs_can_iterate_fsmap(
	struct scrub_ctx	*ctx)
{
	struct getfsmap		fsm[3];
	int			error;

	if (debug && getenv("XFS_SCRUB_NO_FSMAP"))
		return false;

	memset(fsm, 0, 2 * sizeof(struct getfsmap));
	(fsm + 1)->fmv_device = UINT_MAX;
	(fsm + 1)->fmv_block = ULLONG_MAX;
	(fsm + 1)->fmv_owner = ULLONG_MAX;
	(fsm + 1)->fmv_offset = ULLONG_MAX;
	fsm->fmv_count = 3;
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_GETFSMAP, fsm);
	return error == 0 && (fsm->fmv_oflags & FMV_HOF_DEV_T);
}

/* These must correspond to XFS_SCRUB_TYPE_ */
static const struct scrub_descr scrubbers[] = {
	{"superblock",				ST_PERAG},
	{"AG free header",			ST_PERAG},
	{"AG free list",			ST_PERAG},
	{"AG inode header",			ST_PERAG},
	{"freesp by block btree",		ST_PERAG},
	{"freesp by length btree",		ST_PERAG},
	{"inode btree",				ST_PERAG},
	{"free inode btree",			ST_PERAG},
	{"reverse mapping btree",		ST_PERAG},
	{"reference count btree",		ST_PERAG},
	{"inode",				ST_INODE},
	{"inode data block map",		ST_INODE},
	{"inode attr block map",		ST_INODE},
	{"inode CoW block map",			ST_INODE},
	{"realtime bitmap",			ST_FS},
	{"realtime summary",			ST_FS},
	{"realtime reverse mapping btree",	ST_FS},
};

/* Scrub each AG's metadata btrees. */
bool
xfs_scrub_ag_metadata(
	struct scrub_ctx		*ctx,
	xfs_agnumber_t			agno,
	void				*arg)
{
	const struct scrub_descr	*scrubber;
	char				buf[DESCR_BUFSZ];
	struct xfs_scrub_metadata	meta;
	int				type;
	int				error;

	assert(!debug || !getenv("XFS_SCRUB_NO_KERNEL"));

	memset(&meta, 0, sizeof(meta));
	meta.control = agno;
	for (type = 0, scrubber = scrubbers;
	     type <= XFS_SCRUB_TYPE_MAX;
	     type++, scrubber++) {
		if (scrubber->type != ST_PERAG)
			continue;
		snprintf(buf, DESCR_BUFSZ, _("AG %d %s"), agno,
				_(scrubber->name));
		if (debug)
			printf(_("Scrubbing %s.\n"), buf);
		meta.type = type;
		error = ioctl(ctx->mnt_fd, XFS_IOC_SCRUB_METADATA, &meta);
		if (error && errno != ENOENT)
			str_errno(ctx, buf);
	}

	return true;
}

/* Scrub whole-FS metadata btrees. */
bool
xfs_scrub_fs_metadata(
	struct scrub_ctx		*ctx,
	void				*arg)
{
	const struct scrub_descr	*scrubber;
	char				buf[DESCR_BUFSZ];
	struct xfs_scrub_metadata	meta;
	int				type;
	int				error;

	assert(!debug || !getenv("XFS_SCRUB_NO_KERNEL"));

	memset(&meta, 0, sizeof(meta));
	for (type = 0, scrubber = scrubbers;
	     type <= XFS_SCRUB_TYPE_MAX;
	     type++, scrubber++) {
		if (scrubber->type != ST_FS)
			continue;
		snprintf(buf, DESCR_BUFSZ, _("%s"), _(scrubber->name));
		if (debug)
			printf(_("Scrubbing %s.\n"), buf);
		meta.type = type;
		error = ioctl(ctx->mnt_fd, XFS_IOC_SCRUB_METADATA, &meta);
		if (error && errno != ENOENT)
			str_errno(ctx, buf);
	}

	return true;
}

/* Scrub inode metadata btrees. */
bool
xfs_scrub_inode_metadata(
	struct scrub_ctx		*ctx,
	uint64_t			ino,
	int				fd)
{
	const struct scrub_descr	*scrubber;
	char				buf[DESCR_BUFSZ];
	struct xfs_scrub_metadata	meta;
	int				type;
	int				error;

	assert(!debug || !getenv("XFS_SCRUB_NO_KERNEL"));

	memset(&meta, 0, sizeof(meta));
	for (type = 0, scrubber = scrubbers;
	     type <= XFS_SCRUB_TYPE_MAX;
	     type++, scrubber++) {
		if (scrubber->type != ST_INODE)
			continue;
		snprintf(buf, DESCR_BUFSZ, _("inode %"PRIu64" %s"),
				ino, _(scrubber->name));
		meta.type = type;
		error = xfsctl("", fd, XFS_IOC_SCRUB_METADATA, &meta);
		if (error && errno != ENOENT)
			str_errno(ctx, buf);
	}

	return true;
}

/* Test the availability of the kernel scrub ioctl. */
bool
xfs_can_scrub_metadata(
	struct scrub_ctx		*ctx)
{
	struct xfs_scrub_metadata	meta;
	int				error;

	if (debug && getenv("XFS_SCRUB_NO_KERNEL"))
		return false;

	memset(&meta, 0xFF, sizeof(meta));
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_SCRUB_METADATA,
			&meta);
	return error == -1 && errno == EINVAL;
}
