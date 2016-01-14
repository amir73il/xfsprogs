/*
 * Copyright (c) 2014 Red Hat, Inc.
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
#include "libxfs_priv.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_alloc.h"
#include "xfs_btree.h"
#include "xfs_rmap_btree.h"
#include "xfs_trace.h"
#include "xfs_cksum.h"


/*
 * Reverse map btree.
 *
 * This is a per-ag tree used to track the owner of a given extent. Owner
 * records are inserted when an extent is allocated, and removed when an extent
 * is freed. For existing filesystems, there can only be one owner of an extent,
 * usually an inode or some other metadata structure like a AG btree.
 *
 * Initial thoughts are that the
 * value of the owner field needs external flags to define what it means, and
 * hence we need a flags field in the record. This means the record is going to
 * be larger than 16 bytes (agbno,len,owner = 16 bytes), so maybe this isn't the
 * best idea. Initially just implement the owner field - we can probably steal
 * bits from the extent length field for type descriptors given that MAXEXTLEN
 * is only 21 bits if we want to store the type as well. Keep in mind that if we
 * want to do this there are still restrictions on the length of extents we
 * track in the rmap btree (see comments on xfs_rmap_free()).
 *
 * The rmap btree is part of the free space management, so blocks for the tree
 * are sourced from the agfl. Hence we need transaction reservation support for
 * this tree so that the freelist is always large enough. This also impacts on
 * the minimum space we need to leave free in the AG.
 *
 * The tree is ordered by block number - there's no need to order/search by
 * extent size for  online updating/management of the tree, and the reverse
 * lookups are going to be "who owns this block" and so are by-block ordering is
 * perfect for this.
 *
 * XXX: open question is how to handle blocks that are owned by the freespace
 * tree blocks. Right now they will be classified when they are moved to the
 * freelist or removed from the freelist. i.e. the extent allocation/freeing
 * will mark the extents allocated as owned by the AG.
 */
STATIC struct xfs_btree_cur *
xfs_rmapbt_dup_cursor(
	struct xfs_btree_cur	*cur)
{
	return xfs_rmapbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno);
}

STATIC void
xfs_rmapbt_set_root(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	int			inc)
{
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	xfs_agnumber_t		seqno = be32_to_cpu(agf->agf_seqno);
	int			btnum = cur->bc_btnum;
	struct xfs_perag	*pag = xfs_perag_get(cur->bc_mp, seqno);

	ASSERT(ptr->s != 0);

	agf->agf_roots[btnum] = ptr->s;
	be32_add_cpu(&agf->agf_levels[btnum], inc);
	pag->pagf_levels[btnum] += inc;
	xfs_perag_put(pag);

	xfs_alloc_log_agf(cur->bc_tp, agbp, XFS_AGF_ROOTS | XFS_AGF_LEVELS);
}

STATIC int
xfs_rmapbt_alloc_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*start,
	union xfs_btree_ptr	*new,
	int			*stat)
{
	int			error;
	xfs_agblock_t		bno;

	XFS_BTREE_TRACE_CURSOR(cur, XBT_ENTRY);

	/* Allocate the new block from the freelist. If we can't, give up.  */
	error = xfs_alloc_get_freelist(cur->bc_tp, cur->bc_private.a.agbp,
				       &bno, 1);
	if (error) {
		XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
		return error;
	}

	if (bno == NULLAGBLOCK) {
		XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
		*stat = 0;
		return 0;
	}

	xfs_extent_busy_reuse(cur->bc_mp, cur->bc_private.a.agno, bno, 1, false);

	xfs_trans_agbtree_delta(cur->bc_tp, 1);
	new->s = cpu_to_be32(bno);

	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 1;
	return 0;
}

STATIC int
xfs_rmapbt_free_block(
	struct xfs_btree_cur	*cur,
	struct xfs_buf		*bp)
{
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	xfs_agblock_t		bno;
	int			error;

	bno = xfs_daddr_to_agbno(cur->bc_mp, XFS_BUF_ADDR(bp));
	error = xfs_alloc_put_freelist(cur->bc_tp, agbp, NULL, bno, 1);
	if (error)
		return error;

	xfs_extent_busy_insert(cur->bc_tp, be32_to_cpu(agf->agf_seqno), bno, 1,
			      XFS_EXTENT_BUSY_SKIP_DISCARD);
	xfs_trans_agbtree_delta(cur->bc_tp, -1);

	xfs_trans_binval(cur->bc_tp, bp);
	return 0;
}

STATIC int
xfs_rmapbt_get_minrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_rmap_mnr[level != 0];
}

STATIC int
xfs_rmapbt_get_maxrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_rmap_mxr[level != 0];
}

STATIC void
xfs_rmapbt_init_key_from_rec(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	key->rmap.rm_startblock = rec->rmap.rm_startblock;
}

STATIC void
xfs_rmapbt_init_rec_from_key(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	rec->rmap.rm_startblock = key->rmap.rm_startblock;
}

STATIC void
xfs_rmapbt_init_rec_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*rec)
{
	rec->rmap.rm_startblock = cpu_to_be32(cur->bc_rec.r.rm_startblock);
	rec->rmap.rm_blockcount = cpu_to_be32(cur->bc_rec.r.rm_blockcount);
	rec->rmap.rm_owner = cpu_to_be64(cur->bc_rec.r.rm_owner);
}

STATIC void
xfs_rmapbt_init_ptr_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));
	ASSERT(agf->agf_roots[cur->bc_btnum] != 0);

	ptr->s = agf->agf_roots[cur->bc_btnum];
}

STATIC __int64_t
xfs_rmapbt_key_diff(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*key)
{
	struct xfs_rmap_irec	*rec = &cur->bc_rec.r;
	struct xfs_rmap_key	*kp = &key->rmap;

	return (__int64_t)be32_to_cpu(kp->rm_startblock) - rec->rm_startblock;
}

static bool
xfs_rmapbt_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_btree_block	*block = XFS_BUF_TO_BLOCK(bp);
	struct xfs_perag	*pag = bp->b_pag;
	unsigned int		level;

	/*
	 * magic number and level verification
	 *
	 * During growfs operations, we can't verify the exact level or owner as
	 * the perag is not fully initialised and hence not attached to the
	 * buffer.  In this case, check against the maximum tree depth.
	 *
	 * Similarly, during log recovery we will have a perag structure
	 * attached, but the agf information will not yet have been initialised
	 * from the on disk AGF. Again, we can only check against maximum limits
	 * in this case.
	 */
	if (block->bb_magic!= cpu_to_be32(XFS_RMAP_CRC_MAGIC))
		return false;

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return false;
	if (!uuid_equal(&block->bb_u.s.bb_uuid, &mp->m_sb.sb_uuid))
		return false;
	if (block->bb_u.s.bb_blkno != cpu_to_be64(bp->b_bn))
		return false;
	if (pag && be32_to_cpu(block->bb_u.s.bb_owner) != pag->pag_agno)
		return false;

	level = be16_to_cpu(block->bb_level);
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_levels[XFS_BTNUM_RMAPi])
			return false;
	} else if (level >= mp->m_ag_maxlevels)
		return false;

	/* numrecs verification */
	if (be16_to_cpu(block->bb_numrecs) > mp->m_rmap_mxr[level != 0])
		return false;

	/* sibling pointer verification */
	if (!block->bb_u.s.bb_leftsib ||
	    (be32_to_cpu(block->bb_u.s.bb_leftsib) >= mp->m_sb.sb_agblocks &&
	     block->bb_u.s.bb_leftsib != cpu_to_be32(NULLAGBLOCK)))
		return false;
	if (!block->bb_u.s.bb_rightsib ||
	    (be32_to_cpu(block->bb_u.s.bb_rightsib) >= mp->m_sb.sb_agblocks &&
	     block->bb_u.s.bb_rightsib != cpu_to_be32(NULLAGBLOCK)))
		return false;

	return true;
}

static void
xfs_rmapbt_read_verify(
	struct xfs_buf	*bp)
{
	if (!xfs_btree_sblock_verify_crc(bp))
		xfs_buf_ioerror(bp, -EFSBADCRC);
	else if (!xfs_rmapbt_verify(bp))
		xfs_buf_ioerror(bp, -EFSCORRUPTED);

	if (bp->b_error) {
		trace_xfs_btree_corrupt(bp, _RET_IP_);
		xfs_verifier_error(bp);
	}
}

static void
xfs_rmapbt_write_verify(
	struct xfs_buf	*bp)
{
	if (!xfs_rmapbt_verify(bp)) {
		trace_xfs_btree_corrupt(bp, _RET_IP_);
		xfs_buf_ioerror(bp, -EFSCORRUPTED);
		xfs_verifier_error(bp);
		return;
	}
	xfs_btree_sblock_calc_crc(bp);

}

const struct xfs_buf_ops xfs_rmapbt_buf_ops = {
	.name			= "xfs_rmapbt",
	.verify_read		= xfs_rmapbt_read_verify,
	.verify_write		= xfs_rmapbt_write_verify,
};


#if defined(DEBUG) || defined(XFS_WARN)
STATIC int
xfs_rmapbt_keys_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*k1,
	union xfs_btree_key	*k2)
{
	return be32_to_cpu(k1->rmap.rm_startblock) <
	       be32_to_cpu(k2->rmap.rm_startblock);
}

STATIC int
xfs_rmapbt_recs_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*r1,
	union xfs_btree_rec	*r2)
{
	return be32_to_cpu(r1->rmap.rm_startblock) +
		be32_to_cpu(r1->rmap.rm_blockcount) <=
		be32_to_cpu(r2->rmap.rm_startblock);
}
#endif	/* DEBUG */

static const struct xfs_btree_ops xfs_rmapbt_ops = {
	.rec_len		= sizeof(struct xfs_rmap_rec),
	.key_len		= sizeof(struct xfs_rmap_key),

	.dup_cursor		= xfs_rmapbt_dup_cursor,
	.set_root		= xfs_rmapbt_set_root,
	.alloc_block		= xfs_rmapbt_alloc_block,
	.free_block		= xfs_rmapbt_free_block,
	.get_minrecs		= xfs_rmapbt_get_minrecs,
	.get_maxrecs		= xfs_rmapbt_get_maxrecs,
	.init_key_from_rec	= xfs_rmapbt_init_key_from_rec,
	.init_rec_from_key	= xfs_rmapbt_init_rec_from_key,
	.init_rec_from_cur	= xfs_rmapbt_init_rec_from_cur,
	.init_ptr_from_cur	= xfs_rmapbt_init_ptr_from_cur,
	.key_diff		= xfs_rmapbt_key_diff,
	.buf_ops		= &xfs_rmapbt_buf_ops,
#if defined(DEBUG) || defined(XFS_WARN)
	.keys_inorder		= xfs_rmapbt_keys_inorder,
	.recs_inorder		= xfs_rmapbt_recs_inorder,
#endif
};

/*
 * Allocate a new allocation btree cursor.
 */
struct xfs_btree_cur *
xfs_rmapbt_init_cursor(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp,
	xfs_agnumber_t		agno)
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	struct xfs_btree_cur	*cur;

	cur = kmem_zone_zalloc(xfs_btree_cur_zone, KM_SLEEP);
	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = XFS_BTNUM_RMAP;
	cur->bc_flags = XFS_BTREE_CRC_BLOCKS;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_ops = &xfs_rmapbt_ops;
	cur->bc_nlevels = be32_to_cpu(agf->agf_levels[XFS_BTNUM_RMAP]);

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;

	return cur;
}

/*
 * Calculate number of records in an rmap btree block.
 */
int
xfs_rmapbt_maxrecs(
	struct xfs_mount	*mp,
	int			blocklen,
	int			leaf)
{
	blocklen -= XFS_RMAP_BLOCK_LEN;

	if (leaf)
		return blocklen / sizeof(struct xfs_rmap_rec);
	return blocklen /
		(sizeof(struct xfs_rmap_key) + sizeof(xfs_rmap_ptr_t));
}
