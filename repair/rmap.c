/*
 * Copyright (c) 2016 Oracle.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <libxfs.h>
#include "btree.h"
#include "err_protos.h"
#include "libxlog.h"
#include "incore.h"
#include "globals.h"
#include "dinode.h"
#include "slab.h"
#include "rmap.h"

#undef RMAP_DEBUG

#ifdef RMAP_DEBUG
# define dbg_printf(f, a...)  do {printf(f, ## a); fflush(stdout); } while (0)
#else
# define dbg_printf(f, a...)
#endif

/* per-AG rmap object anchor */
struct xfs_ag_rmap {
	struct xfs_slab	*ar_rmaps;		/* rmap observations, p4 */
	struct xfs_slab	*ar_raw_rmaps;		/* unmerged rmaps */
};

static struct xfs_ag_rmap *ag_rmaps;
static bool rmapbt_suspect;

/*
 * Compare rmap observations for array sorting.
 */
static int
rmap_compare(
	const void		*a,
	const void		*b)
{
	const struct xfs_rmap_irec	*pa;
	const struct xfs_rmap_irec	*pb;

	pa = a; pb = b;
	if (pa->rm_startblock < pb->rm_startblock)
		return -1;
	else if (pa->rm_startblock > pb->rm_startblock)
		return 1;
	else if (pa->rm_owner < pb->rm_owner)
		return -1;
	else if (pa->rm_owner > pb->rm_owner)
		return 1;
	else if (pa->rm_offset < pb->rm_offset)
		return -1;
	else if (pa->rm_offset > pb->rm_offset)
		return 1;
	else
		return 0;
}

/*
 * Returns true if we must reconstruct either the reference count or reverse
 * mapping trees.
 */
bool
needs_rmap_work(
	struct xfs_mount	*mp)
{
	return xfs_sb_version_hasrmapbt(&mp->m_sb);
}

/*
 * Initialize per-AG reverse map data.
 */
void
init_rmaps(
	struct xfs_mount	*mp)
{
	xfs_agnumber_t		i;
	int			error;

	if (!needs_rmap_work(mp))
		return;

	ag_rmaps = calloc(mp->m_sb.sb_agcount, sizeof(struct xfs_ag_rmap));
	if (!ag_rmaps)
		do_error(_("couldn't allocate per-AG reverse map roots\n"));

	for (i = 0; i < mp->m_sb.sb_agcount; i++) {
		error = init_slab(&ag_rmaps[i].ar_rmaps,
				sizeof(struct xfs_rmap_irec));
		if (error)
			do_error(
_("Insufficient memory while allocating reverse mapping slabs."));
		error = init_slab(&ag_rmaps[i].ar_raw_rmaps,
				  sizeof(struct xfs_rmap_irec));
		if (error)
			do_error(
_("Insufficient memory while allocating raw metadata reverse mapping slabs."));
	}
}

/*
 * Free the per-AG reverse-mapping data.
 */
void
free_rmaps(
	struct xfs_mount	*mp)
{
	xfs_agnumber_t		i;

	if (!needs_rmap_work(mp))
		return;

	for (i = 0; i < mp->m_sb.sb_agcount; i++) {
		free_slab(&ag_rmaps[i].ar_rmaps);
		free_slab(&ag_rmaps[i].ar_raw_rmaps);
	}
	free(ag_rmaps);
	ag_rmaps = NULL;
}

/*
 * Add an observation about a block mapping in an inode's data or attribute
 * fork for later btree reconstruction.
 */
int
add_rmap(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	int			whichfork,
	struct xfs_bmbt_irec	*irec)
{
	struct xfs_slab		*rmaps;
	struct xfs_rmap_irec	rmap;
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;

	if (!needs_rmap_work(mp))
		return 0;

	agno = XFS_FSB_TO_AGNO(mp, irec->br_startblock);
	agbno = XFS_FSB_TO_AGBNO(mp, irec->br_startblock);
	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(agbno + irec->br_blockcount <= mp->m_sb.sb_agblocks);
	ASSERT(ino != NULLFSINO);
	ASSERT(whichfork == XFS_DATA_FORK || whichfork == XFS_ATTR_FORK);

	rmaps = ag_rmaps[agno].ar_rmaps;
	rmap.rm_owner = ino;
	rmap.rm_offset = irec->br_startoff;
	if (whichfork == XFS_ATTR_FORK)
		rmap.rm_offset |= XFS_RMAP_OFF_ATTR;
	rmap.rm_startblock = agbno;
	rmap.rm_blockcount = irec->br_blockcount;
	if (irec->br_state == XFS_EXT_UNWRITTEN)
		rmap.rm_blockcount |= XFS_RMAP_LEN_UNWRITTEN;
	return slab_add(rmaps, &rmap);
}

/* add a raw rmap; these will be merged later */
static int
__add_raw_rmap(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len,
	uint64_t		owner,
	bool			is_attr,
	bool			is_bmbt)
{
	struct xfs_rmap_irec	rmap;

	ASSERT(len != 0);
	rmap.rm_owner = owner;
	rmap.rm_offset = 0;
	if (is_attr)
		rmap.rm_offset |= XFS_RMAP_OFF_ATTR;
	if (is_bmbt)
		rmap.rm_offset |= XFS_RMAP_OFF_BMBT;
	rmap.rm_startblock = agbno;
	rmap.rm_blockcount = len;
	return slab_add(ag_rmaps[agno].ar_raw_rmaps, &rmap);
}

/*
 * Add a reverse mapping for an inode fork's block mapping btree block.
 */
int
add_bmbt_rmap(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	int			whichfork,
	xfs_fsblock_t		fsbno)
{
	xfs_agnumber_t		agno;
	xfs_agblock_t		agbno;

	if (!needs_rmap_work(mp))
		return 0;

	agno = XFS_FSB_TO_AGNO(mp, fsbno);
	agbno = XFS_FSB_TO_AGBNO(mp, fsbno);
	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(agbno + 1 <= mp->m_sb.sb_agblocks);

	return __add_raw_rmap(mp, agno, agbno, 1, ino,
			whichfork == XFS_ATTR_FORK, true);
}

/*
 * Add a reverse mapping for a per-AG fixed metadata extent.
 */
int
add_ag_rmap(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len,
	uint64_t		owner)
{
	if (!needs_rmap_work(mp))
		return 0;

	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agno < mp->m_sb.sb_agcount);
	ASSERT(agbno + len <= mp->m_sb.sb_agblocks);

	return __add_raw_rmap(mp, agno, agbno, len, owner, false, false);
}

/*
 * Decide if two reverse-mapping records can be merged.
 */
static bool
mergeable_rmaps(
	struct xfs_rmap_irec	*r1,
	struct xfs_rmap_irec	*r2)
{
	if (r1->rm_startblock + r1->rm_blockcount != r2->rm_startblock)
		return false;
	if (r1->rm_owner != r2->rm_owner)
		return false;
	if (XFS_RMAP_NON_INODE_OWNER(r2->rm_owner))
		return true;
	/* must be an inode owner */
	if (XFS_RMAP_IS_ATTR_FORK(r1->rm_offset) ^
	    XFS_RMAP_IS_ATTR_FORK(r2->rm_offset))
		return false;
	if (XFS_RMAP_IS_BMBT(r1->rm_offset) || XFS_RMAP_IS_BMBT(r2->rm_offset))
		return XFS_RMAP_IS_BMBT(r1->rm_offset) &&
		       XFS_RMAP_IS_BMBT(r2->rm_offset);
	return r1->rm_offset + r1->rm_blockcount == r2->rm_offset;
}

/*
 * Merge adjacent raw rmaps and add them to the main rmap list.
 */
int
fold_raw_rmaps(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_slab_cursor	*cur = NULL;
	struct xfs_rmap_irec	*prev, *rec;
	size_t			old_sz;
	int			error;

	old_sz = slab_count(ag_rmaps[agno].ar_rmaps);
	if (slab_count(ag_rmaps[agno].ar_raw_rmaps) == 0)
		goto no_raw;
	qsort_slab(ag_rmaps[agno].ar_raw_rmaps, rmap_compare);
	error = init_slab_cursor(ag_rmaps[agno].ar_raw_rmaps, rmap_compare,
			&cur);
	if (error)
		goto err;

	prev = pop_slab_cursor(cur);
	rec = pop_slab_cursor(cur);
	while (rec) {
		if (mergeable_rmaps(prev, rec)) {
			prev->rm_blockcount += rec->rm_blockcount;
			rec = pop_slab_cursor(cur);
			continue;
		}
		error = slab_add(ag_rmaps[agno].ar_rmaps, prev);
		if (error)
			goto err;
		prev = rec;
		rec = pop_slab_cursor(cur);
	}
	if (prev) {
		error = slab_add(ag_rmaps[agno].ar_rmaps, prev);
		if (error)
			goto err;
	}
	free_slab(&ag_rmaps[agno].ar_raw_rmaps);
	error = init_slab(&ag_rmaps[agno].ar_raw_rmaps,
			sizeof(struct xfs_rmap_irec));
	if (error)
		do_error(
_("Insufficient memory while allocating raw metadata reverse mapping slabs."));
no_raw:
	if (old_sz)
		qsort_slab(ag_rmaps[agno].ar_rmaps, rmap_compare);
err:
	free_slab_cursor(&cur);
	return error;
}

static int
find_first_zero_bit(
	__uint64_t	mask)
{
	int		n;
	int		b = 0;

	for (n = 0; n < sizeof(mask) * NBBY && (mask & 1); n++, mask >>= 1)
		b++;

	return b;
}

static int
popcnt(
	__uint64_t	mask)
{
	int		n;
	int		b = 0;

	if (mask == 0)
		return 0;

	for (n = 0; n < sizeof(mask) * NBBY; n++, mask >>= 1)
		if (mask & 1)
			b++;

	return b;
}

/*
 * Add an allocation group's fixed metadata to the rmap list.  This includes
 * sb/agi/agf/agfl headers, inode chunks, and the log.
 */
int
add_fixed_ag_rmap_data(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	xfs_fsblock_t		fsbno;
	xfs_agblock_t		agbno;
	ino_tree_node_t		*ino_rec;
	xfs_agino_t		agino;
	int			error;
	int			startidx;
	int			nr;

	if (!needs_rmap_work(mp))
		return 0;

	/* sb/agi/agf/agfl headers */
	error = add_ag_rmap(mp, agno, 0, XFS_BNO_BLOCK(mp),
			XFS_RMAP_OWN_FS);
	if (error)
		goto out;

	/* inodes */
	ino_rec = findfirst_inode_rec(agno);
	for (; ino_rec != NULL; ino_rec = next_ino_rec(ino_rec)) {
		if (xfs_sb_version_hassparseinodes(&mp->m_sb)) {
			startidx = find_first_zero_bit(ino_rec->ir_sparse);
			nr = XFS_INODES_PER_CHUNK - popcnt(ino_rec->ir_sparse);
		} else {
			startidx = 0;
			nr = XFS_INODES_PER_CHUNK;
		}
		nr /= mp->m_sb.sb_inopblock;
		if (nr == 0)
			nr = 1;
		agino = ino_rec->ino_startnum + startidx;
		agbno = XFS_AGINO_TO_AGBNO(mp, agino);
		if (XFS_AGINO_TO_OFFSET(mp, agino) == 0) {
			error = add_ag_rmap(mp, agno, agbno, nr,
					XFS_RMAP_OWN_INODES);
			if (error)
				goto out;
		}
	}

	/* log */
	fsbno = mp->m_sb.sb_logstart;
	if (fsbno && XFS_FSB_TO_AGNO(mp, fsbno) == agno) {
		agbno = XFS_FSB_TO_AGBNO(mp, mp->m_sb.sb_logstart);
		error = add_ag_rmap(mp, agno, agbno, mp->m_sb.sb_logblocks,
				XFS_RMAP_OWN_LOG);
		if (error)
			goto out;
	}
out:
	return error;
}

#ifdef RMAP_DEBUG
static void
dump_rmap(
	const char		*msg,
	xfs_agnumber_t		agno,
	struct xfs_rmap_irec	*rmap)
{
	printf("%s: %p agno=%u pblk=%llu ino=%lld lblk=%llu len=%u\n", msg,
		rmap,
		(unsigned)agno,
		(unsigned long long)rmap->rm_startblock,
		(unsigned long long)rmap->rm_owner,
		(unsigned long long)rmap->rm_offset,
		(unsigned)rmap->rm_blockcount);
}
#else
# define dump_rmap(m, a, r)
#endif

/*
 * Return the number of rmap objects for an AG.
 */
size_t
rmap_record_count(
	struct xfs_mount		*mp,
	xfs_agnumber_t		agno)
{
	return slab_count(ag_rmaps[agno].ar_rmaps);
}

/*
 * Return a slab cursor that will return rmap objects in order.
 */
int
init_rmap_cursor(
	xfs_agnumber_t		agno,
	struct xfs_slab_cursor	**cur)
{
	return init_slab_cursor(ag_rmaps[agno].ar_rmaps, rmap_compare, cur);
}

/*
 * Disable the refcount btree check.
 */
void
rmap_avoid_check(void)
{
	rmapbt_suspect = true;
}

/*
 * Compare the observed reverse mappings against what's in the ag btree.
 */
int
check_rmaps(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_slab_cursor	*rm_cur;
	struct xfs_btree_cur	*bt_cur = NULL;
	int			error;
	int			have;
	int			i;
	struct xfs_buf		*agbp = NULL;
	struct xfs_rmap_irec	*rm_rec;
	struct xfs_rmap_irec	tmp;
	struct xfs_perag	*pag;		/* per allocation group data */

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;
	if (rmapbt_suspect) {
		if (no_modify && agno == 0)
			do_warn(_("would rebuild corrupt rmap btrees.\n"));
		return 0;
	}

	/* Create cursors to refcount structures */
	error = init_rmap_cursor(agno, &rm_cur);
	if (error)
		return error;

	error = xfs_alloc_read_agf(mp, NULL, agno, 0, &agbp);
	if (error)
		goto err;

	/* Leave the per-ag data "uninitialized" since we rewrite it later */
	pag = xfs_perag_get(mp, agno);
	pag->pagf_init = 0;
	xfs_perag_put(pag);

	bt_cur = xfs_rmapbt_init_cursor(mp, NULL, agbp, agno);
	if (!bt_cur) {
		error = -ENOMEM;
		goto err;
	}

	rm_rec = pop_slab_cursor(rm_cur);
	while (rm_rec) {
		/* Look for a rmap record in the btree */
		error = xfs_rmap_lookup_eq(bt_cur, rm_rec->rm_startblock,
				rm_rec->rm_blockcount, rm_rec->rm_owner,
				rm_rec->rm_offset, &have);
		if (error)
			goto err;
		if (!have) {
			do_warn(
_("Missing reverse-mapping record for (%u/%u) %slen %u owner %"PRIx64" \
%s%soff %"PRIx64"\n"),
				agno, rm_rec->rm_startblock,
				XFS_RMAP_IS_UNWRITTEN(rm_rec->rm_blockcount) ?
					_("unwritten ") : "",
				XFS_RMAP_LEN(rm_rec->rm_blockcount),
				rm_rec->rm_owner,
				XFS_RMAP_IS_ATTR_FORK(rm_rec->rm_offset) ?
					_("attr ") : "",
				XFS_RMAP_IS_BMBT(rm_rec->rm_offset) ?
					_("bmbt ") : "",
				XFS_RMAP_OFF(rm_rec->rm_offset));
			goto next_loop;
		}

		error = xfs_rmap_get_rec(bt_cur, &tmp, &i);
		if (error)
			goto err;
		if (!i) {
			do_warn(
_("Unretrievable reverse-mapping record for (%u/%u) %slen %u owner %"PRIx64" \
%s%soff %"PRIx64"\n"),
				agno, rm_rec->rm_startblock,
				XFS_RMAP_IS_UNWRITTEN(rm_rec->rm_blockcount) ?
					_("unwritten ") : "",
				XFS_RMAP_LEN(rm_rec->rm_blockcount),
				rm_rec->rm_owner,
				XFS_RMAP_IS_ATTR_FORK(rm_rec->rm_offset) ?
					_("attr ") : "",
				XFS_RMAP_IS_BMBT(rm_rec->rm_offset) ?
					_("bmbt ") : "",
				XFS_RMAP_OFF(rm_rec->rm_offset));
			goto next_loop;
		}

		/* Compare each refcount observation against the btree's */
		if (tmp.rm_startblock != rm_rec->rm_startblock ||
		    tmp.rm_blockcount != rm_rec->rm_blockcount ||
		    tmp.rm_owner != rm_rec->rm_owner ||
		    tmp.rm_offset != rm_rec->rm_offset)
			do_warn(
_("Incorrect reverse-mapping: saw (%u/%u) %slen %u owner %"PRIx64" %s%soff \
%"PRIx64"; should be (%u/%u) %slen %u owner %"PRIx64" %s%soff %"PRIx64"\n"),
				agno, tmp.rm_startblock,
				XFS_RMAP_IS_UNWRITTEN(tmp.rm_blockcount) ?
					_("unwritten ") : "",
				XFS_RMAP_LEN(tmp.rm_blockcount),
				tmp.rm_owner,
				XFS_RMAP_IS_ATTR_FORK(tmp.rm_offset) ?
					_("attr ") : "",
				XFS_RMAP_IS_BMBT(tmp.rm_offset) ?
					_("bmbt ") : "",
				XFS_RMAP_OFF(tmp.rm_offset),
				agno, rm_rec->rm_startblock,
				XFS_RMAP_IS_UNWRITTEN(rm_rec->rm_blockcount) ?
					_("unwritten ") : "",
				XFS_RMAP_LEN(rm_rec->rm_blockcount),
				rm_rec->rm_owner,
				XFS_RMAP_IS_ATTR_FORK(rm_rec->rm_offset) ?
					_("attr ") : "",
				XFS_RMAP_IS_BMBT(rm_rec->rm_offset) ?
					_("bmbt ") : "",
				XFS_RMAP_OFF(rm_rec->rm_offset));
next_loop:
		rm_rec = pop_slab_cursor(rm_cur);
	}

err:
	if (bt_cur)
		xfs_btree_del_cursor(bt_cur, XFS_BTREE_NOERROR);
	if (agbp)
		libxfs_putbuf(agbp);
	free_slab_cursor(&rm_cur);
	return 0;
}
