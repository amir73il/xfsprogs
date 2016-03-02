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
	int		ar_flcount;		/* agfl entries from leftover */
						/* agbt allocations */
	struct xfs_slab	*ar_refcount_items;	/* refcount items, p4-5 */
};

static struct xfs_ag_rmap *ag_rmaps;
static bool rmapbt_suspect;
static bool refcbt_suspect;

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
	return xfs_sb_version_hasreflink(&mp->m_sb) ||
	       xfs_sb_version_hasrmapbt(&mp->m_sb);
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
		error = init_slab(&ag_rmaps[i].ar_refcount_items,
				  sizeof(struct xfs_refcount_irec));
		if (error)
			do_error(
_("Insufficient memory while allocating refcount item slabs."));
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
		free_slab(&ag_rmaps[i].ar_refcount_items);
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
	rmap.rm_flags = 0;
	if (whichfork == XFS_ATTR_FORK)
		rmap.rm_flags |= XFS_RMAP_ATTR_FORK;
	rmap.rm_startblock = agbno;
	rmap.rm_blockcount = irec->br_blockcount;
	if (irec->br_state == XFS_EXT_UNWRITTEN)
		rmap.rm_flags |= XFS_RMAP_UNWRITTEN;
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
	rmap.rm_flags = 0;
	if (is_attr)
		rmap.rm_flags |= XFS_RMAP_ATTR_FORK;
	if (is_bmbt)
		rmap.rm_flags |= XFS_RMAP_BMBT;
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
	if ((r1->rm_flags & XFS_RMAP_ATTR_FORK) ^
	    (r2->rm_flags & XFS_RMAP_ATTR_FORK))
		return false;
	if ((r1->rm_flags & XFS_RMAP_BMBT) || (r2->rm_flags & XFS_RMAP_BMBT))
		return  (r1->rm_flags & XFS_RMAP_BMBT) &&
			(r2->rm_flags & XFS_RMAP_BMBT);
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

/*
 * Copy the per-AG btree reverse-mapping data into the rmapbt.
 *
 * At rmapbt reconstruction time, the rmapbt will be populated _only_ with
 * rmaps for file extents, inode chunks, AG headers, and bmbt blocks.  While
 * building the AG btrees we can record all the blocks allocated for each
 * btree, but we cannot resolve the conflict between the fact that one has to
 * finish allocating the space for the rmapbt before building the bnobt and the
 * fact that allocating blocks for the bnobt requires adding rmapbt entries.
 * Therefore we record in-core the rmaps for each btree and here use the
 * libxfs rmap functions to finish building the rmap btree.
 *
 * During AGF/AGFL reconstruction in phase 5, rmaps for the AG btrees are
 * recorded in memory.  The rmapbt has not been set up yet, so we need to be
 * able to "expand" the AGFL without updating the rmapbt.  After we've written
 * out the new AGF header the new rmapbt is available, so this function reads
 * each AGFL to generate rmap entries.  These entries are merged with the AG
 * btree rmap entries, and then we use libxfs' rmap functions to add them to
 * the rmapbt, after which it is fully regenerated.
 */
int
store_ag_btree_rmap_data(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_slab_cursor	*rm_cur;
	struct xfs_rmap_irec	*rm_rec = NULL;
	struct xfs_btree_cur	*bt_cur = NULL;
	struct xfs_buf		*agbp = NULL;
	struct xfs_buf		*agflbp = NULL;
	struct xfs_trans	*tp;
	struct xfs_trans_res tres = {0};
	__be32			*agfl_bno, *b;
	int			error = 0;

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;

	/* Release the ar_rmaps; they were put into the rmapbt during p5. */
	free_slab(&ag_rmaps[agno].ar_rmaps);
	error = init_slab(&ag_rmaps[agno].ar_rmaps,
				  sizeof(struct xfs_rmap_irec));
	if (error)
		goto err;

	/* Add the AGFL blocks to the rmap list */
	error = xfs_trans_read_buf(
			mp, NULL, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, agno, XFS_AGFL_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &agflbp, &xfs_agfl_buf_ops);
	if (error)
		goto err;

	agfl_bno = XFS_BUF_TO_AGFL_BNO(mp, agflbp);
	agfl_bno += ag_rmaps[agno].ar_flcount;
	b = agfl_bno;
	while (*b != NULLAGBLOCK && b - agfl_bno <= XFS_AGFL_SIZE(mp)) {
		error = add_ag_rmap(mp, agno, be32_to_cpu(*b), 1,
				XFS_RMAP_OWN_AG);
		if (error)
			goto err;
		b++;
	}
	libxfs_putbuf(agflbp);
	agflbp = NULL;

	/* Merge all the raw rmaps into the main list */
	error = fold_raw_rmaps(mp, agno);
	if (error)
		goto err;

	/* Create cursors to refcount structures */
	error = init_slab_cursor(ag_rmaps[agno].ar_rmaps, rmap_compare,
			&rm_cur);
	if (error)
		goto err;

	/* Insert rmaps into the btree one at a time */
	rm_rec = pop_slab_cursor(rm_cur);
	while (rm_rec) {
		tp = libxfs_trans_alloc(mp, 0);
		if (!tp) {
			error = -ENOMEM;
			goto err_slab;
		}

		error = -libxfs_trans_reserve(tp, &tres, 16, 0);
		if (error)
			goto err_trans;

		error = xfs_alloc_read_agf(mp, tp, agno, 0, &agbp);
		if (error)
			goto err_trans;

		bt_cur = xfs_rmapbt_init_cursor(mp, tp, agbp, agno);
		if (!bt_cur) {
			error = -ENOMEM;
			goto err_agbp;
		}

		error = xfs_rmapbt_insert(bt_cur, rm_rec->rm_startblock,
				rm_rec->rm_blockcount, rm_rec->rm_owner,
				rm_rec->rm_offset, rm_rec->rm_flags);
		if (error)
			goto err_rmapcur;

		xfs_btree_del_cursor(bt_cur, XFS_BTREE_NOERROR);
		error = -libxfs_trans_commit(tp);
		if (error)
			goto err_slab;

		fix_freelist(mp, agno, false);

		rm_rec = pop_slab_cursor(rm_cur);
	}

	free_slab_cursor(&rm_cur);
	return 0;

err_rmapcur:
	xfs_btree_del_cursor(bt_cur, XFS_BTREE_ERROR);
err_agbp:
	libxfs_putbuf(agbp);
err_trans:
	libxfs_trans_cancel(tp);
err_slab:
	free_slab_cursor(&rm_cur);
err:
	if (agflbp)
		libxfs_putbuf(agflbp);
	printf("FAIL err %d\n", error);
	return error;
}

#ifdef RMAP_DEBUG
static void
dump_rmap(
	const char		*msg,
	xfs_agnumber_t		agno,
	struct xfs_rmap_irec	*rmap)
{
	printf("%s: %p agno=%u pblk=%llu owner=%lld lblk=%llu len=%u flags=0x%x\n",
		msg, rmap,
		(unsigned)agno,
		(unsigned long long)rmap->rm_startblock,
		(unsigned long long)rmap->rm_owner,
		(unsigned long long)rmap->rm_offset,
		(unsigned)rmap->rm_blockcount,
		(unsigned)rmap->rm_flags);
}
#else
# define dump_rmap(m, a, r)
#endif

/*
 * Rebuilding the Reference Count & Reverse Mapping Btrees
 *
 * The reference count (refcnt) and reverse mapping (rmap) btrees are rebuilt
 * during phase 5, like all other AG btrees.  Therefore, reverse mappings must
 * be processed into reference counts at the end of phase 4, and the rmaps must
 * be recorded during phase 4.  There is a need to access the rmaps in physical
 * block order, but no particular need for random access, so the slab.c code
 * provides a big logical array (consisting of smaller slabs) and some inorder
 * iterator functions.
 *
 * Once we've recorded all the reverse mappings, we're ready to translate the
 * rmaps into refcount entries.  Imagine the rmap entries as rectangles
 * representing extents of physical blocks, and that the rectangles can be laid
 * down to allow them to overlap each other; then we know that we must emit
 * a refcnt btree entry wherever the amount of overlap changes, i.e. the
 * emission stimulus is level-triggered:
 *
 *                 -    ---
 *       --      ----- ----   ---        ------
 * --   ----     ----------- ----     ---------
 * -------------------------------- -----------
 * ^ ^  ^^ ^^    ^ ^^ ^^^  ^^^^  ^ ^^ ^  ^     ^
 * 2 1  23 21    3 43 234  2123  1 01 2  3     0
 *
 * For our purposes, a rmap is a tuple (startblock, len, fileoff, owner).
 *
 * Note that in the actual refcnt btree we don't store the refcount < 2 cases
 * because the bnobt tells us which blocks are free; single-use blocks aren't
 * recorded in the bnobt or the refcntbt.  If the rmapbt supports storing
 * multiple entries covering a given block we could theoretically dispense with
 * the refcntbt and simply count rmaps, but that's inefficient in the (hot)
 * write path, so we'll take the cost of the extra tree to save time.  Also
 * there's no guarantee that rmap will be enabled.
 *
 * Given an array of rmaps sorted by physical block number, a starting physical
 * block (sp), a bag to hold rmaps that cover sp, and the next physical
 * block where the level changes (np), we can reconstruct the refcount
 * btree as follows:
 *
 * While there are still unprocessed rmaps in the array,
 *  - Set sp to the physical block (pblk) of the next unprocessed rmap.
 *  - Add to the bag all rmaps in the array where startblock == sp.
 *  - Set np to the physical block where the bag size will change.
 *    This is the minimum of (the pblk of the next unprocessed rmap) and
 *    (startblock + len of each rmap in the bag).
 *  - Record the bag size as old_bag_size.
 *
 *  - While the bag isn't empty,
 *     - Remove from the bag all rmaps where startblock + len == np.
 *     - Add to the bag all rmaps in the array where startblock == np.
 *     - If the bag size isn't old_bag_size, store the refcount entry
 *       (sp, np - sp, bag_size) in the refcnt btree.
 *     - If the bag is empty, break out of the inner loop.
 *     - Set old_bag_size to the bag size
 *     - Set sp = np.
 *     - Set np to the physical block where the bag size will change.
 *       This is the minimum of (the pblk of the next unprocessed rmap) and
 *       (startblock + len of each rmap in the bag).
 *
 * An implementation detail is that because this processing happens during
 * phase 4, the refcount entries are stored in an array so that phase 5 can
 * load them into the refcount btree.  The rmaps can be loaded directly into
 * the rmap btree during phase 5 as well.
 */

/*
 * Mark all inodes in the reverse-mapping observation stack as requiring the
 * reflink inode flag, if the stack depth is greater than 1.
 */
static void
mark_inode_rl(
	struct xfs_mount	*mp,
	struct xfs_bag		*rmaps)
{
	xfs_agnumber_t		iagno;
	struct xfs_rmap_irec	*rmap;
	struct ino_tree_node	*irec;
	int			off;
	size_t			idx;
	xfs_agino_t		ino;

	if (bag_count(rmaps) < 2)
		return;

	/* Reflink flag accounting */
	foreach_bag_ptr(rmaps, idx, rmap) {
		ASSERT(!XFS_RMAP_NON_INODE_OWNER(rmap->rm_owner));
		iagno = XFS_INO_TO_AGNO(mp, rmap->rm_owner);
		ino = XFS_INO_TO_AGINO(mp, rmap->rm_owner);
		pthread_mutex_lock(&ag_locks[iagno].lock);
		irec = find_inode_rec(mp, iagno, ino);
		off = get_inode_offset(mp, rmap->rm_owner, irec);
		/* lock here because we might go outside this ag */
		set_inode_is_rl(irec, off);
		pthread_mutex_unlock(&ag_locks[iagno].lock);
	}
}

/*
 * Emit a refcount object for refcntbt reconstruction during phase 5.
 */
#define REFCOUNT_CLAMP(nr)	((nr) > MAXREFCOUNT ? MAXREFCOUNT : (nr))
static void
refcount_emit(
	struct xfs_mount		*mp,
	xfs_agnumber_t		agno,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len,
	size_t			nr_rmaps)
{
	struct xfs_refcount_irec	rlrec;
	int			error;
	struct xfs_slab		*rlslab;

	rlslab = ag_rmaps[agno].ar_refcount_items;
	ASSERT(nr_rmaps > 0);

	dbg_printf("REFL: agno=%u pblk=%u, len=%u -> refcount=%zu\n",
		agno, agbno, len, nr_rmaps);
	rlrec.rc_startblock = agbno;
	rlrec.rc_blockcount = len;
	rlrec.rc_refcount = REFCOUNT_CLAMP(nr_rmaps);
	error = slab_add(rlslab, &rlrec);
	if (error)
		do_error(
_("Insufficient memory while recreating refcount tree."));
}
#undef REFCOUNT_CLAMP

/*
 * Transform a pile of physical block mapping observations into refcount data
 * for eventual rebuilding of the btrees.
 */
#define RMAP_END(r)	((r)->rm_startblock + (r)->rm_blockcount)
int
compute_refcounts(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_bag		*stack_top = NULL;
	struct xfs_slab		*rmaps;
	struct xfs_slab_cursor	*rmaps_cur;
	struct xfs_rmap_irec	*array_cur;
	struct xfs_rmap_irec	*rmap;
	xfs_agblock_t		sbno;	/* first bno of this rmap set */
	xfs_agblock_t		cbno;	/* first bno of this refcount set */
	xfs_agblock_t		nbno;	/* next bno where rmap set changes */
	size_t			n, idx;
	size_t			old_stack_nr;
	int			error;

	if (!xfs_sb_version_hasreflink(&mp->m_sb))
		return 0;

	rmaps = ag_rmaps[agno].ar_rmaps;

	error = init_slab_cursor(rmaps, rmap_compare, &rmaps_cur);
	if (error)
		return error;

	error = init_bag(&stack_top);
	if (error)
		goto err;

	/* While there are rmaps to be processed... */
	n = 0;
	while (n < slab_count(rmaps)) {
		array_cur = peek_slab_cursor(rmaps_cur);
		sbno = cbno = array_cur->rm_startblock;
		/* Push all rmaps with pblk == sbno onto the stack */
		for (;
		     array_cur && array_cur->rm_startblock == sbno;
		     array_cur = peek_slab_cursor(rmaps_cur)) {
			advance_slab_cursor(rmaps_cur); n++;
			dump_rmap("push0", agno, array_cur);
			error = bag_add(stack_top, array_cur);
			if (error)
				goto err;
		}
		mark_inode_rl(mp, stack_top);

		/* Set nbno to the bno of the next refcount change */
		if (n < slab_count(rmaps))
			nbno = array_cur->rm_startblock;
		else
			nbno = NULLAGBLOCK;
		foreach_bag_ptr(stack_top, idx, rmap) {
			nbno = min(nbno, RMAP_END(rmap));
		}

		/* Emit reverse mappings, if needed */
		ASSERT(nbno > sbno);
		old_stack_nr = bag_count(stack_top);

		/* While stack isn't empty... */
		while (bag_count(stack_top)) {
			/* Pop all rmaps that end at nbno */
			foreach_bag_ptr_reverse(stack_top, idx, rmap) {
				if (RMAP_END(rmap) != nbno)
					continue;
				dump_rmap("pop", agno, rmap);
				error = bag_remove(stack_top, idx);
				if (error)
					goto err;
			}

			/* Push array items that start at nbno */
			for (;
			     array_cur && array_cur->rm_startblock == nbno;
			     array_cur = peek_slab_cursor(rmaps_cur)) {
				advance_slab_cursor(rmaps_cur); n++;
				dump_rmap("push1", agno, array_cur);
				error = bag_add(stack_top, array_cur);
				if (error)
					goto err;
			}
			mark_inode_rl(mp, stack_top);

			/* Emit refcount if necessary */
			ASSERT(nbno > cbno);
			if (bag_count(stack_top) != old_stack_nr) {
				if (old_stack_nr > 1) {
					refcount_emit(mp, agno, cbno,
						      nbno - cbno,
						      old_stack_nr);
				}
				cbno = nbno;
			}

			/* Stack empty, go find the next rmap */
			if (bag_count(stack_top) == 0)
				break;
			old_stack_nr = bag_count(stack_top);
			sbno = nbno;

			/* Set nbno to the bno of the next refcount change */
			if (n < slab_count(rmaps))
				nbno = array_cur->rm_startblock;
			else
				nbno = NULLAGBLOCK;
			foreach_bag_ptr(stack_top, idx, rmap) {
				nbno = min(nbno, RMAP_END(rmap));
			}

			/* Emit reverse mappings, if needed */
			ASSERT(nbno > sbno);
		}
	}
err:
	free_bag(&stack_top);
	free_slab_cursor(&rmaps_cur);

	return error;
}
#undef RMAP_END

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
				rm_rec->rm_offset, rm_rec->rm_flags, &have);
		if (error)
			goto err;
		if (!have) {
			do_warn(
_("Missing reverse-mapping record for (%u/%u) %slen %u owner %"PRId64" \
%s%soff %"PRIu64"\n"),
				agno, rm_rec->rm_startblock,
				(rm_rec->rm_flags & XFS_RMAP_UNWRITTEN) ?
					_("unwritten ") : "",
				rm_rec->rm_blockcount,
				rm_rec->rm_owner,
				(rm_rec->rm_flags & XFS_RMAP_ATTR_FORK) ?
					_("attr ") : "",
				(rm_rec->rm_flags & XFS_RMAP_BMBT) ?
					_("bmbt ") : "",
				rm_rec->rm_offset);
			goto next_loop;
		}

		error = xfs_rmap_get_rec(bt_cur, &tmp, &i);
		if (error)
			goto err;
		if (!i) {
			do_warn(
_("Unretrievable reverse-mapping record for (%u/%u) %slen %u owner %"PRId64" \
%s%soff %"PRIu64"\n"),
				agno, rm_rec->rm_startblock,
				(rm_rec->rm_flags & XFS_RMAP_UNWRITTEN) ?
					_("unwritten ") : "",
				rm_rec->rm_blockcount,
				rm_rec->rm_owner,
				(rm_rec->rm_flags & XFS_RMAP_ATTR_FORK) ?
					_("attr ") : "",
				(rm_rec->rm_flags & XFS_RMAP_BMBT) ?
					_("bmbt ") : "",
				rm_rec->rm_offset);
			goto next_loop;
		}

		/* Compare each refcount observation against the btree's */
		if (tmp.rm_startblock != rm_rec->rm_startblock ||
		    tmp.rm_blockcount != rm_rec->rm_blockcount ||
		    tmp.rm_owner != rm_rec->rm_owner ||
		    tmp.rm_offset != rm_rec->rm_offset ||
		    tmp.rm_flags != rm_rec->rm_flags)
			do_warn(
_("Incorrect reverse-mapping: saw (%u/%u) %slen %u owner %"PRId64" %s%soff \
%"PRIu64"; should be (%u/%u) %slen %u owner %"PRId64" %s%soff %"PRIu64"\n"),
				agno, tmp.rm_startblock,
				(tmp.rm_flags & XFS_RMAP_UNWRITTEN) ?
					_("unwritten ") : "",
				tmp.rm_blockcount,
				tmp.rm_owner,
				(tmp.rm_flags & XFS_RMAP_ATTR_FORK) ?
					_("attr ") : "",
				(tmp.rm_flags & XFS_RMAP_BMBT) ?
					_("bmbt ") : "",
				tmp.rm_offset,
				agno, rm_rec->rm_startblock,
				(rm_rec->rm_flags & XFS_RMAP_UNWRITTEN) ?
					_("unwritten ") : "",
				rm_rec->rm_blockcount,
				rm_rec->rm_owner,
				(rm_rec->rm_flags & XFS_RMAP_ATTR_FORK) ?
					_("attr ") : "",
				(rm_rec->rm_flags & XFS_RMAP_BMBT) ?
					_("bmbt ") : "",
				rm_rec->rm_offset);
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

/*
 * Record that an inode had the reflink flag set when repair started.  The
 * inode reflink flag will be adjusted as necessary.
 */
void
record_inode_reflink_flag(
	struct xfs_mount	*mp,
	struct xfs_dinode	*dino,
	xfs_agnumber_t		agno,
	xfs_agino_t		ino,
	xfs_ino_t		lino)
{
	struct ino_tree_node	*irec;
	int			off;

	ASSERT(XFS_AGINO_TO_INO(mp, agno, ino) == be64_to_cpu(dino->di_ino));
	if (!(be64_to_cpu(dino->di_flags2) & XFS_DIFLAG2_REFLINK))
		return;
	irec = find_inode_rec(mp, agno, ino);
	off = get_inode_offset(mp, lino, irec);
	ASSERT(!inode_was_rl(irec, off));
	set_inode_was_rl(irec, off);
	dbg_printf("set was_rl lino=%llu was=0x%llx\n",
		(unsigned long long)lino, (unsigned long long)irec->ino_was_rl);
}

/*
 * Fix an inode's reflink flag.
 */
static int
fix_inode_reflink_flag(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno,
	xfs_agino_t		agino,
	bool			set)
{
	struct xfs_dinode	*dino;
	struct xfs_buf		*buf;

	if (set)
		do_warn(
_("setting reflink flag on inode %"PRIu64"\n"),
			XFS_AGINO_TO_INO(mp, agno, agino));
	else if (!no_modify) /* && !set */
		do_warn(
_("clearing reflink flag on inode %"PRIu64"\n"),
			XFS_AGINO_TO_INO(mp, agno, agino));
	if (no_modify)
		return 0;

	buf = get_agino_buf(mp, agno, agino, &dino);
	if (!buf)
		return 1;
	ASSERT(XFS_AGINO_TO_INO(mp, agno, agino) == be64_to_cpu(dino->di_ino));
	if (set)
		dino->di_flags2 |= cpu_to_be64(XFS_DIFLAG2_REFLINK);
	else
		dino->di_flags2 &= cpu_to_be64(~XFS_DIFLAG2_REFLINK);
	libxfs_dinode_calc_crc(mp, dino);
	libxfs_writebuf(buf, 0);

	return 0;
}

/*
 * Fix discrepancies between the state of the inode reflink flag and our
 * observations as to whether or not the inode really needs it.
 */
int
fix_inode_reflink_flags(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct ino_tree_node	*irec;
	int			bit;
	__uint64_t		was;
	__uint64_t		is;
	__uint64_t		diff;
	__uint64_t		mask;
	int			error = 0;
	xfs_agino_t		agino;

	/*
	 * Update the reflink flag for any inode where there's a discrepancy
	 * between the inode flag and whether or not we found any reflinked
	 * extents.
	 */
	for (irec = findfirst_inode_rec(agno);
	     irec != NULL;
	     irec = next_ino_rec(irec)) {
		ASSERT((irec->ino_was_rl & irec->ir_free) == 0);
		ASSERT((irec->ino_is_rl & irec->ir_free) == 0);
		was = irec->ino_was_rl;
		is = irec->ino_is_rl;
		if (was == is)
			continue;
		diff = was ^ is;
		dbg_printf("mismatch ino=%llu was=0x%lx is=0x%lx dif=0x%lx\n",
			(unsigned long long)XFS_AGINO_TO_INO(mp, agno,
						irec->ino_startnum),
			was, is, diff);

		for (bit = 0, mask = 1; bit < 64; bit++, mask <<= 1) {
			agino = bit + irec->ino_startnum;
			if (!(diff & mask))
				continue;
			else if (was & mask)
				error = fix_inode_reflink_flag(mp, agno, agino,
						false);
			else if (is & mask)
				error = fix_inode_reflink_flag(mp, agno, agino,
						true);
			else
				ASSERT(0);
			if (error)
				do_error(
_("Unable to fix reflink flag on inode %"PRIu64".\n"),
					XFS_AGINO_TO_INO(mp, agno, agino));
		}
	}

	return error;
}

/*
 * Return the number of refcount objects for an AG.
 */
size_t
refcount_record_count(
	struct xfs_mount		*mp,
	xfs_agnumber_t		agno)
{
	return slab_count(ag_rmaps[agno].ar_refcount_items);
}

/*
 * Return a slab cursor that will return refcount objects in order.
 */
int
init_refcount_cursor(
	xfs_agnumber_t		agno,
	struct xfs_slab_cursor	**cur)
{
	return init_slab_cursor(ag_rmaps[agno].ar_refcount_items, NULL, cur);
}

/*
 * Disable the refcount btree check.
 */
void
refcount_avoid_check(void)
{
	refcbt_suspect = true;
}

/*
 * Compare the observed reference counts against what's in the ag btree.
 */
int
check_refcounts(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_slab_cursor	*rl_cur;
	struct xfs_btree_cur	*bt_cur = NULL;
	int			error;
	int			have;
	int			i;
	struct xfs_buf		*agbp = NULL;
	struct xfs_refcount_irec	*rl_rec;
	struct xfs_refcount_irec	tmp;
	struct xfs_perag	*pag;		/* per allocation group data */

	if (!xfs_sb_version_hasreflink(&mp->m_sb))
		return 0;
	if (refcbt_suspect) {
		if (no_modify && agno == 0)
			do_warn(_("would rebuild corrupt refcount btrees.\n"));
		return 0;
	}

	/* Create cursors to refcount structures */
	error = init_refcount_cursor(agno, &rl_cur);
	if (error)
		return error;

	error = xfs_alloc_read_agf(mp, NULL, agno, 0, &agbp);
	if (error)
		goto err;

	/* Leave the per-ag data "uninitialized" since we rewrite it later */
	pag = xfs_perag_get(mp, agno);
	pag->pagf_init = 0;
	xfs_perag_put(pag);

	bt_cur = xfs_refcountbt_init_cursor(mp, NULL, agbp, agno, NULL);
	if (!bt_cur) {
		error = -ENOMEM;
		goto err;
	}

	rl_rec = pop_slab_cursor(rl_cur);
	while (rl_rec) {
		/* Look for a refcount record in the btree */
		error = xfs_refcountbt_lookup_le(bt_cur,
				rl_rec->rc_startblock, &have);
		if (error)
			goto err;
		if (!have) {
			do_warn(
_("Missing reference count record for (%u/%u) len %u count %u\n"),
				agno, rl_rec->rc_startblock,
				rl_rec->rc_blockcount, rl_rec->rc_refcount);
			goto next_loop;
		}

		error = xfs_refcountbt_get_rec(bt_cur, &tmp, &i);
		if (error)
			goto err;
		if (!i) {
			do_warn(
_("Missing reference count record for (%u/%u) len %u count %u\n"),
				agno, rl_rec->rc_startblock,
				rl_rec->rc_blockcount, rl_rec->rc_refcount);
			goto next_loop;
		}

		/* Compare each refcount observation against the btree's */
		if (tmp.rc_startblock != rl_rec->rc_startblock ||
		    tmp.rc_blockcount < rl_rec->rc_blockcount ||
		    tmp.rc_refcount < rl_rec->rc_refcount)
			do_warn(
_("Incorrect reference count: saw (%u/%u) len %u nlinks %u; should be (%u/%u) len %u nlinks %u\n"),
				agno, tmp.rc_startblock, tmp.rc_blockcount,
				tmp.rc_refcount, agno, rl_rec->rc_startblock,
				rl_rec->rc_blockcount, rl_rec->rc_refcount);
next_loop:
		rl_rec = pop_slab_cursor(rl_cur);
	}

err:
	if (bt_cur)
		xfs_btree_del_cursor(bt_cur, XFS_BTREE_NOERROR);
	if (agbp)
		libxfs_putbuf(agbp);
	free_slab_cursor(&rl_cur);
	return 0;
}

/*
 * Regenerate the AGFL so that we don't run out of it while rebuilding the
 * rmap btree.  If skip_rmapbt is true, don't update the rmapbt (most probably
 * because we're updating the rmapbt).
 */
void
fix_freelist(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno,
	bool			skip_rmapbt)
{
	xfs_alloc_arg_t		args;
	xfs_trans_t		*tp;
	struct xfs_trans_res	tres = {0};
	int			flags;
	int			error;

	memset(&args, 0, sizeof(args));
	args.tp = tp = libxfs_trans_alloc(mp, 0);
	args.mp = mp;
	args.agno = agno;
	args.alignment = 1;
	args.pag = xfs_perag_get(mp, agno);
	libxfs_trans_reserve(tp, &tres,
			     xfs_alloc_min_freelist(mp, args.pag), 0);
	/*
	 * Prior to rmapbt, all we had to do to fix the freelist is "expand"
	 * the fresh AGFL header from empty to full.  That hasn't changed.  For
	 * rmapbt, however, things change a bit.
	 *
	 * When we're stuffing the rmapbt with the AG btree rmaps the tree can
	 * expand, so we need to keep the AGFL well-stocked for the expansion.
	 * However, this expansion can cause the bnobt/cntbt to shrink, which
	 * can make the AGFL eligible for shrinking.  Shrinking involves
	 * freeing rmapbt entries, but since we haven't finished loading the
	 * rmapbt with the btree rmaps it's possible for the remove operation
	 * to fail.  The AGFL block is large enough at this point to absorb any
	 * blocks freed from the bnobt/cntbt, so we can disable shrinking.
	 *
	 * During the initial AGFL regeneration during AGF generation in phase5
	 * we must also disable rmapbt modifications because the AGF that
	 * libxfs reads does not yet point to the new rmapbt.  These initial
	 * AGFL entries are added just prior to adding the AG btree block rmaps
	 * to the rmapbt.  It's ok to pass NOSHRINK here too, since the AGFL is
	 * empty and cannot shrink.
	 */
	flags = XFS_ALLOC_FLAG_NOSHRINK;
	if (skip_rmapbt)
		flags |= XFS_ALLOC_FLAG_NORMAP;
	error = libxfs_alloc_fix_freelist(&args, flags);
	xfs_perag_put(args.pag);
	if (error) {
		do_error(_("failed to fix AGFL on AG %d, error %d\n"),
				agno, error);
	}
	libxfs_trans_commit(tp);
}

/*
 * Remember how many AGFL entries came from excess AG btree allocations and
 * therefore already have rmap entries.
 */
void
rmap_store_agflcount(
	struct xfs_mount	*mp,
	xfs_agnumber_t	agno,
	int 		count)
{
	if (!needs_rmap_work(mp))
		return;

	ag_rmaps[agno].ar_flcount = count;
}