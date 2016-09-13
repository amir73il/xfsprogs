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
	const char		*descr,
	void			*fshandle,
	uint64_t		first_ino,
	uint64_t		last_ino,
	xfs_inode_iter_fn	fn,
	void			*arg)
{
	struct xfs_fsop_bulkreq	bulkreq;
	struct xfs_bstat	*bstatbuf;
	struct xfs_bstat	*p;
	struct xfs_bstat	*endp;
	struct xfs_handle	handle;
	__s32			buflenout = 0;
	bool			moveon = true;
	int			error;

	assert(!debug_tweak_on("XFS_SCRUB_NO_BULKSTAT"));

	bstatbuf = calloc(BSTATBUF_NR, sizeof(struct xfs_bstat));
	if (!bstatbuf) {
		str_errno(ctx, descr);
		return false;
	}

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
			moveon = fn(ctx, &handle, p, arg);
			if (!moveon)
				goto out;
			if (xfs_scrub_excessive_errors(ctx)) {
				moveon = false;
				goto out;
			}
		}
	}

	if (error) {
		str_errno(ctx, descr);
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

	if (debug_tweak_on("XFS_SCRUB_NO_BULKSTAT"))
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
	const char		*descr,
	int			fd,
	int			whichfork,
	struct xfs_bmap		*key,
	xfs_bmap_iter_fn	fn,
	void			*arg)
{
	struct fsxattr		fsx;
	struct getbmapx		*map;
	struct getbmapx		*p;
	struct xfs_bmap		bmap;
	char			bmap_descr[DESCR_BUFSZ];
	bool			moveon = true;
	xfs_off_t		new_off;
	int			getxattr_type;
	int			i;
	int			error;

	assert(!debug_tweak_on("XFS_SCRUB_NO_BMAP"));

	switch (whichfork) {
	case XFS_ATTR_FORK:
		snprintf(bmap_descr, DESCR_BUFSZ, _("%s attr"), descr);
		break;
	case XFS_COW_FORK:
		snprintf(bmap_descr, DESCR_BUFSZ, _("%s CoW"), descr);
		break;
	case XFS_DATA_FORK:
		snprintf(bmap_descr, DESCR_BUFSZ, _("%s data"), descr);
		break;
	default:
		assert(0);
	}

	map = calloc(BMAP_NR, sizeof(struct getbmapx));
	if (!map) {
		str_errno(ctx, bmap_descr);
		return false;
	}

	map->bmv_offset = BTOBB(key->bm_offset);
	map->bmv_block = BTOBB(key->bm_physical);
	if (key->bm_length == 0)
		map->bmv_length = ULLONG_MAX;
	else
		map->bmv_length = BTOBB(key->bm_length);
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
		str_errno(ctx, bmap_descr);
		moveon = false;
		goto out;
	}

	while ((error = xfsctl(bmap_descr, fd, XFS_IOC_GETBMAPX, map)) == 0) {

		for (i = 0, p = &map[i + 1]; i < map->bmv_entries; i++, p++) {
			bmap.bm_offset = BBTOB(p->bmv_offset);
			bmap.bm_physical = BBTOB(p->bmv_block);
			bmap.bm_length = BBTOB(p->bmv_length);
			bmap.bm_flags = p->bmv_oflags;
			moveon = fn(ctx, bmap_descr, fd, whichfork, &fsx,
					&bmap, arg);
			if (!moveon)
				goto out;
			if (xfs_scrub_excessive_errors(ctx)) {
				moveon = false;
				goto out;
			}
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
		str_errno(ctx, bmap_descr);
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

	if (debug_tweak_on("XFS_SCRUB_NO_BMAP"))
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
	const char		*descr,
	struct fsmap		*keys,
	xfs_fsmap_iter_fn	fn,
	void			*arg)
{
	struct fsmap_head	*head;
	struct fsmap		*p;
	bool			moveon = true;
	int			i;
	int			error;

	assert(!debug_tweak_on("XFS_SCRUB_NO_FSMAP"));

	head = malloc(fsmap_sizeof(FSMAP_NR));
	if (!head) {
		str_errno(ctx, descr);
		return false;
	}

	memset(head, 0, sizeof(*head));
	memcpy(head->fmh_keys, keys, sizeof(struct fsmap) * 2);
	head->fmh_count = FSMAP_NR;

	while ((error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_GETFSMAP,
				head)) == 0) {

		for (i = 0, p = head->fmh_recs; i < head->fmh_entries; i++, p++) {
			moveon = fn(ctx, descr, p, arg);
			if (!moveon)
				goto out;
			if (xfs_scrub_excessive_errors(ctx)) {
				moveon = false;
				goto out;
			}
		}

		if (head->fmh_entries == 0)
			break;
		p = &head->fmh_recs[head->fmh_entries - 1];
		if (p->fmr_flags & FMR_OF_LAST)
			break;

		head->fmh_keys[0] = *p;
	}

	if (error) {
		str_errno(ctx, descr);
		moveon = false;
	}
out:
	free(head);
	return moveon;
}

/* Does the kernel support getfsmap? */
bool
xfs_can_iterate_fsmap(
	struct scrub_ctx	*ctx)
{
	struct fsmap_head	head;
	int			error;

	if (debug_tweak_on("XFS_SCRUB_NO_FSMAP"))
		return false;

	memset(&head, 0, sizeof(struct fsmap_head));
	head.fmh_keys[1].fmr_device = UINT_MAX;
	head.fmh_keys[1].fmr_physical = ULLONG_MAX;
	head.fmh_keys[1].fmr_owner = ULLONG_MAX;
	head.fmh_keys[1].fmr_offset = ULLONG_MAX;
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_GETFSMAP, &head);
	return error == 0 && (head.fmh_oflags & FMH_OF_DEV_T);
}

/* Online scrub and repair. */

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

/* These must correspond to XFS_SCRUB_TYPE_ */
static const struct scrub_descr scrubbers[] = {
	{"dummy",				ST_NONE},
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
	{"record",				ST_INODE},
	{"data block map",			ST_INODE},
	{"attr block map",			ST_INODE},
	{"CoW block map",			ST_INODE},
	{"directory entries",			ST_INODE},
	{"extended attributes",			ST_INODE},
	{"symbolic link",			ST_INODE},
	{"realtime bitmap",			ST_FS},
	{"realtime summary",			ST_FS},
	{"realtime reverse mapping btree",	ST_FS},
};

/* Format a scrub description. */
static void
format_scrub_descr(
	char				*buf,
	size_t				buflen,
	int				fd,
	unsigned long long		ctl,
	const struct scrub_descr	*sc)
{
	struct stat			sb;

	switch (sc->type) {
	case ST_PERAG:
		snprintf(buf, buflen, _("AG %llu %s"), ctl, _(sc->name));
		break;
	case ST_INODE:
		if (ctl == 0 && fd >= 0) {
			fstat(fd, &sb);
			ctl = sb.st_ino;
		}
		snprintf(buf, buflen, _("inode %llu %s"), ctl, _(sc->name));
		break;
	case ST_FS:
		snprintf(buf, buflen, _("%s"), _(sc->name));
		break;
	case ST_NONE:
		assert(0);
		break;
	}
}

/* Do we need to repair something? */
static inline bool
xfs_scrub_needs_repair(
	struct xfs_scrub_metadata	*sm)
{
	return sm->flags & XFS_SCRUB_FLAG_CORRUPT;
}

/* Can we optimize something? */
static inline bool
xfs_scrub_needs_preen(
	struct xfs_scrub_metadata	*sm)
{
	return sm->flags & XFS_SCRUB_FLAG_PREEN;
}

enum check_outcome {
	CHECK_OK,
	CHECK_REPAIR,
	CHECK_PREEN,
};

/* Do a read-only check of some metadata. */
static bool
xfs_check_metadata(
	struct scrub_ctx		*ctx,
	int				fd,
	unsigned int			type,
	unsigned long long		ctl,
	enum check_outcome		*outcome)
{
	struct xfs_scrub_metadata	meta = {0};
	const struct scrub_descr	*sc;
	char				buf[DESCR_BUFSZ];
	int				error;

	assert(!debug_tweak_on("XFS_SCRUB_NO_KERNEL"));

	sc = &scrubbers[type];
	*outcome = CHECK_OK;
	meta.control = ctl;
	meta.type = type;
	meta.flags = 0;
	format_scrub_descr(buf, DESCR_BUFSZ, fd, ctl, sc);

	error = ioctl(fd, XFS_IOC_SCRUB_METADATA, &meta);
	dbg_printf("check fd %d type %s ctl %llu error %d errno %d flags %xh\n",
			fd, sc->name, ctl, error, errno, meta.flags);
	if (error) {
		/* Metadata not present, just skip it. */
		if (errno == ENOENT)
			return true;

		/* Operational error. */
		str_errno(ctx, buf);
		return true;
	} else if (!xfs_scrub_needs_repair(&meta) &&
		   !xfs_scrub_needs_preen(&meta)) {
		/* Clean operation, no corruption or preening detected. */
		return true;
	} else if (xfs_scrub_needs_repair(&meta) &&
		   ctx->mode < SCRUB_MODE_REPAIR) {
		/* Corrupt, but we're not in repair mode. */
		str_error(ctx, buf, _("Repairs are required."));
		return true;
	} else if (xfs_scrub_needs_preen(&meta) &&
		   ctx->mode < SCRUB_MODE_PREEN) {
		/* Preenable, but we're not in preen mode. */
		str_info(ctx, buf, _("Optimization is possible."));
		return true;
	}

	/* Save for later. */
	if (xfs_scrub_needs_repair(&meta))
		*outcome = CHECK_REPAIR;
	else
		*outcome = CHECK_PREEN;
	return true;
}

/* Repair some metadata. */
static bool
xfs_repair_metadata(
	struct scrub_ctx		*ctx,
	int				fd,
	int				type,
	unsigned long long		ctl,
	enum check_outcome		fix)
{
	struct xfs_scrub_metadata	meta = {0};
	const struct scrub_descr	*sc;
	char				buf[DESCR_BUFSZ];
	int				error;

	assert(!debug_tweak_on("XFS_SCRUB_NO_KERNEL"));
	assert(fix != CHECK_OK);

	sc = &scrubbers[type];
	meta.control = ctl;
	meta.type = type;
	meta.flags |= XFS_SCRUB_FLAG_REPAIR;
	format_scrub_descr(buf, DESCR_BUFSZ, fd, ctl, sc);

	if (fix == CHECK_REPAIR)
		record_repair(ctx, buf, _("Attempting repair."));
	else
		record_preen(ctx, buf, _("Attempting optimization."));
	error = ioctl(fd, XFS_IOC_SCRUB_METADATA, &meta);
	if (error) {
		switch (errno) {
		case EINVAL:
		case EOPNOTSUPP:
		case ENOTTY:
			/* Kernel doesn't know how to repair this. */
			goto fix_offline;
		case EROFS:
			/* Read-only filesystem, can't fix. */
			if (verbose || debug || fix == CHECK_REPAIR)
				str_info(ctx, buf,
_("Read-only filesystem; cannot make changes."));
			/* fall through */
		case ENOENT:
			/* Metadata not present, just skip it. */
			return true;
		default:
			/* Operational error. */
			str_errno(ctx, buf);
			return true;
		}
	} else if (xfs_scrub_needs_repair(&meta)) {
fix_offline:
		/* Corrupt, must fix offline. */
		str_error(ctx, buf, _("Offline repair required."));
		return true;
	} else {
		/* Clean operation, no corruption detected. */
		return true;
	}
}

struct repair_item {
	struct list_head	list;
	unsigned int		type;
	unsigned long long	ctl;
	enum check_outcome	fix;
};

/* Scrub metadata, saving corruption reports for later. */
static bool
xfs_scrub_metadata(
	struct scrub_ctx		*ctx,
	enum scrub_type			scrub_type,
	xfs_agnumber_t			agno,
	struct list_head		*repair_list)
{
	const struct scrub_descr	*sc;
	struct repair_item		*ri;
	enum check_outcome		fix;
	int				type;
	bool				moveon;

	sc = scrubbers;
	for (type = 0; type <= XFS_SCRUB_TYPE_MAX; type++, sc++) {
		if (sc->type != scrub_type)
			continue;

		/* Check the item. */
		moveon = xfs_check_metadata(ctx, ctx->mnt_fd, type, agno, &fix);
		if (!moveon)
			return false;
		if (!fix)
			continue;

		/* Schedule this item for later repairs. */
		ri = malloc(sizeof(struct repair_item));
		if (!ri) {
			str_errno(ctx, _("repair list"));
			return false;
		}
		ri->type = type;
		ri->ctl = agno;
		ri->fix = fix;
		list_add_tail(&ri->list, repair_list);
	}

	return true;
}

/* Scrub each AG's metadata btrees. */
bool
xfs_scrub_ag_metadata(
	struct scrub_ctx		*ctx,
	xfs_agnumber_t			agno,
	struct list_head		*repair_list)
{
	return xfs_scrub_metadata(ctx, ST_PERAG, agno, repair_list);
}

/* Scrub whole-FS metadata btrees. */
bool
xfs_scrub_fs_metadata(
	struct scrub_ctx		*ctx,
	struct list_head		*repair_list)
{
	return xfs_scrub_metadata(ctx, ST_FS, 0, repair_list);
}

/* Repair everything on this list. */
bool
xfs_repair_metadata_list(
	struct scrub_ctx		*ctx,
	struct list_head		*repair_list)
{
	struct repair_item		*ri;
	struct repair_item		*n;
	bool				moveon;

	list_for_each_entry(ri, repair_list, list) {
		moveon = xfs_repair_metadata(ctx, ctx->mnt_fd, ri->type,
				ri->ctl, ri->fix);
		if (!moveon)
			break;
	}

	list_for_each_entry_safe(ri, n, repair_list, list) {
		list_del(&ri->list);
		free(ri);
	}

	return !xfs_scrub_excessive_errors(ctx);
}

/* Scrub inode metadata. */
static bool
__xfs_scrub_file(
	struct scrub_ctx		*ctx,
	uint64_t			ino,
	int				fd,
	unsigned int			type)
{
	const struct scrub_descr	*sc;
	enum check_outcome		fix;
	bool				moveon;

	assert(type <= XFS_SCRUB_TYPE_MAX);
	sc = &scrubbers[type];
	assert(sc->type == ST_INODE);

	/* Scrub the piece of metadata. */
	moveon = xfs_check_metadata(ctx, fd, type, ino, &fix);
	if (!moveon || xfs_scrub_excessive_errors(ctx))
		return false;
	else if (!fix)
		return true;

	/* Repair the metadata. */
	moveon = xfs_repair_metadata(ctx, fd, type, ino, fix);
	if (!moveon)
		return false;
	return !xfs_scrub_excessive_errors(ctx);
}

#define XFS_SCRUB_FILE_PART(name, flagname) \
bool \
xfs_scrub_##name( \
	struct scrub_ctx		*ctx, \
	uint64_t			ino, \
	int				fd) \
{ \
	return __xfs_scrub_file(ctx, ino, fd, XFS_SCRUB_TYPE_##flagname); \
}
XFS_SCRUB_FILE_PART(inode_fields,	INODE)
XFS_SCRUB_FILE_PART(data_fork,		BMBTD)
XFS_SCRUB_FILE_PART(attr_fork,		BMBTA)
XFS_SCRUB_FILE_PART(cow_fork,		BMBTC)
XFS_SCRUB_FILE_PART(dir,		DIR)
XFS_SCRUB_FILE_PART(attr,		XATTR)
XFS_SCRUB_FILE_PART(symlink,		SYMLINK)

/* Test the availability of a kernel scrub command. */
static bool
__xfs_scrub_test(
	struct scrub_ctx		*ctx,
	unsigned int			type)
{
	struct xfs_scrub_metadata	meta = {0};
	int				error;

	if (debug_tweak_on("XFS_SCRUB_NO_KERNEL"))
		return false;

	meta.type = type;
	error = xfsctl(ctx->mntpoint, ctx->mnt_fd, XFS_IOC_SCRUB_METADATA,
			&meta);
	return error == 0 || errno == ENOENT;
}

#define XFS_CAN_SCRUB_TEST(name, flagname) \
bool \
xfs_can_scrub_##name( \
	struct scrub_ctx		*ctx) \
{ \
	return __xfs_scrub_test(ctx, XFS_SCRUB_TYPE_##flagname); \
}
XFS_CAN_SCRUB_TEST(fs_metadata,		SB)
XFS_CAN_SCRUB_TEST(inode,		INODE)
XFS_CAN_SCRUB_TEST(bmap,		BMBTD)
XFS_CAN_SCRUB_TEST(dir,			DIR)
XFS_CAN_SCRUB_TEST(attr,		XATTR)
XFS_CAN_SCRUB_TEST(symlink,		SYMLINK)
