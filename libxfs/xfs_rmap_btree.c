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
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_alloc.h"
#include "xfs_btree.h"
#include "xfs_rmap.h"
#include "xfs_rmap_btree.h"
#include "xfs_trace.h"
#include "xfs_cksum.h"
#include "xfs_ag_resv.h"

/*
 * Reverse map btree.
 *
 * This is a per-ag tree used to track the owner(s) of a given extent. With
 * reflink it is possible for there to be multiple owners, which is a departure
 * from classic XFS. Owner records for data extents are inserted when the
 * extent is mapped and removed when an extent is unmapped.  Owner records for
 * all other block types (i.e. metadata) are inserted when an extent is
 * allocated and removed when an extent is freed. There can only be one owner
 * of a metadata extent, usually an inode or some other metadata structure like
 * an AG btree.
 *
 * The rmap btree is part of the free space management, so blocks for the tree
 * are sourced from the agfl. Hence we need transaction reservation support for
 * this tree so that the freelist is always large enough. This also impacts on
 * the minimum space we need to leave free in the AG.
 *
 * The tree is ordered by [ag block, owner, offset]. This is a large key size,
 * but it is the only way to enforce unique keys when a block can be owned by
 * multiple files at any offset. There's no need to order/search by extent
 * size for online updating/management of the tree. It is intended that most
 * reverse lookups will be to find the owner(s) of a particular block, or to
 * try to recover tree and file data from corrupt primary metadata.
 */

static struct xfs_btree_cur *
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
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
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

	trace_xfs_rmapbt_alloc_block(cur->bc_mp, cur->bc_private.a.agno,
			bno, 1);
	if (bno == NULLAGBLOCK) {
		XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
		*stat = 0;
		return 0;
	}

	xfs_extent_busy_reuse(cur->bc_mp, cur->bc_private.a.agno, bno, 1,
			false);

	xfs_trans_agbtree_delta(cur->bc_tp, 1);
	new->s = cpu_to_be32(bno);
	be32_add_cpu(&agf->agf_rmap_blocks, 1);
	xfs_alloc_log_agf(cur->bc_tp, agbp, XFS_AGF_RMAP_BLOCKS);

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
	trace_xfs_rmapbt_free_block(cur->bc_mp, cur->bc_private.a.agno,
			bno, 1);
	be32_add_cpu(&agf->agf_rmap_blocks, -1);
	xfs_alloc_log_agf(cur->bc_tp, agbp, XFS_AGF_RMAP_BLOCKS);
	error = xfs_alloc_put_freelist(cur->bc_tp, agbp, NULL, bno, 1);
	if (error)
		return error;

	xfs_extent_busy_insert(cur->bc_tp, be32_to_cpu(agf->agf_seqno), bno, 1,
			      XFS_EXTENT_BUSY_SKIP_DISCARD);
	xfs_trans_agbtree_delta(cur->bc_tp, -1);

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
	key->rmap.rm_owner = rec->rmap.rm_owner;
	key->rmap.rm_offset = rec->rmap.rm_offset;
}

/*
 * The high key for a reverse mapping record can be computed by shifting
 * the startblock and offset to the highest value that would still map
 * to that record.  In practice this means that we add blockcount-1 to
 * the startblock for all records, and if the record is for a data/attr
 * fork mapping, we add blockcount-1 to the offset too.
 */
STATIC void
xfs_rmapbt_init_high_key_from_rec(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	__uint64_t		off;
	int			adj;

	adj = be32_to_cpu(rec->rmap.rm_blockcount) - 1;

	key->rmap.rm_startblock = rec->rmap.rm_startblock;
	be32_add_cpu(&key->rmap.rm_startblock, adj);
	key->rmap.rm_owner = rec->rmap.rm_owner;
	key->rmap.rm_offset = rec->rmap.rm_offset;
	if (XFS_RMAP_NON_INODE_OWNER(be64_to_cpu(rec->rmap.rm_owner)) ||
	    XFS_RMAP_IS_BMBT_BLOCK(be64_to_cpu(rec->rmap.rm_offset)))
		return;
	off = be64_to_cpu(key->rmap.rm_offset);
	off = (XFS_RMAP_OFF(off) + adj) | (off & ~XFS_RMAP_OFF_MASK);
	key->rmap.rm_offset = cpu_to_be64(off);
}

STATIC void
xfs_rmapbt_init_rec_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*rec)
{
	rec->rmap.rm_startblock = cpu_to_be32(cur->bc_rec.r.rm_startblock);
	rec->rmap.rm_blockcount = cpu_to_be32(cur->bc_rec.r.rm_blockcount);
	rec->rmap.rm_owner = cpu_to_be64(cur->bc_rec.r.rm_owner);
	rec->rmap.rm_offset = cpu_to_be64(
			xfs_rmap_irec_offset_pack(&cur->bc_rec.r));
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
	__u64			x, y;
	__int64_t		d;

	d = (__int64_t)be32_to_cpu(kp->rm_startblock) - rec->rm_startblock;
	if (d)
		return d;

	x = be64_to_cpu(kp->rm_owner);
	y = rec->rm_owner;
	if (x > y)
		return 1;
	else if (y > x)
		return -1;

	x = XFS_RMAP_OFF(be64_to_cpu(kp->rm_offset));
	y = rec->rm_offset;
	if (x > y)
		return 1;
	else if (y > x)
		return -1;
	return 0;
}

STATIC __int64_t
xfs_rmapbt_diff_two_keys(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*k1,
	union xfs_btree_key	*k2)
{
	struct xfs_rmap_key	*kp1 = &k1->rmap;
	struct xfs_rmap_key	*kp2 = &k2->rmap;
	__int64_t		d;
	__u64			x, y;

	d = (__int64_t)be32_to_cpu(kp1->rm_startblock) -
		       be32_to_cpu(kp2->rm_startblock);
	if (d)
		return d;

	x = be64_to_cpu(kp1->rm_owner);
	y = be64_to_cpu(kp2->rm_owner);
	if (x > y)
		return 1;
	else if (y > x)
		return -1;

	x = XFS_RMAP_OFF(be64_to_cpu(kp1->rm_offset));
	y = XFS_RMAP_OFF(be64_to_cpu(kp2->rm_offset));
	if (x > y)
		return 1;
	else if (y > x)
		return -1;
	return 0;
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
	if (block->bb_magic != cpu_to_be32(XFS_RMAP_CRC_MAGIC))
		return false;

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return false;
	if (!xfs_btree_sblock_v5hdr_verify(bp))
		return false;

	level = be16_to_cpu(block->bb_level);
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_levels[XFS_BTNUM_RMAPi])
			return false;
	} else if (level >= mp->m_rmap_maxlevels)
		return false;

	return xfs_btree_sblock_verify(bp, mp->m_rmap_mxr[level != 0]);
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
	__uint32_t		x;
	__uint32_t		y;
	__uint64_t		a;
	__uint64_t		b;

	x = be32_to_cpu(k1->rmap.rm_startblock);
	y = be32_to_cpu(k2->rmap.rm_startblock);
	if (x < y)
		return 1;
	else if (x > y)
		return 0;
	a = be64_to_cpu(k1->rmap.rm_owner);
	b = be64_to_cpu(k2->rmap.rm_owner);
	if (a < b)
		return 1;
	else if (a > b)
		return 0;
	a = XFS_RMAP_OFF(be64_to_cpu(k1->rmap.rm_offset));
	b = XFS_RMAP_OFF(be64_to_cpu(k2->rmap.rm_offset));
	if (a <= b)
		return 1;
	return 0;
}

STATIC int
xfs_rmapbt_recs_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*r1,
	union xfs_btree_rec	*r2)
{
	__uint32_t		x;
	__uint32_t		y;
	__uint64_t		a;
	__uint64_t		b;

	x = be32_to_cpu(r1->rmap.rm_startblock);
	y = be32_to_cpu(r2->rmap.rm_startblock);
	if (x < y)
		return 1;
	else if (x > y)
		return 0;
	a = be64_to_cpu(r1->rmap.rm_owner);
	b = be64_to_cpu(r2->rmap.rm_owner);
	if (a < b)
		return 1;
	else if (a > b)
		return 0;
	a = XFS_RMAP_OFF(be64_to_cpu(r1->rmap.rm_offset));
	b = XFS_RMAP_OFF(be64_to_cpu(r2->rmap.rm_offset));
	if (a <= b)
		return 1;
	return 0;
}
#endif	/* DEBUG */

static const struct xfs_btree_ops xfs_rmapbt_ops = {
	.rec_len		= sizeof(struct xfs_rmap_rec),
	.key_len		= 2 * sizeof(struct xfs_rmap_key),

	.dup_cursor		= xfs_rmapbt_dup_cursor,
	.set_root		= xfs_rmapbt_set_root,
	.alloc_block		= xfs_rmapbt_alloc_block,
	.free_block		= xfs_rmapbt_free_block,
	.get_minrecs		= xfs_rmapbt_get_minrecs,
	.get_maxrecs		= xfs_rmapbt_get_maxrecs,
	.init_key_from_rec	= xfs_rmapbt_init_key_from_rec,
	.init_high_key_from_rec	= xfs_rmapbt_init_high_key_from_rec,
	.init_rec_from_cur	= xfs_rmapbt_init_rec_from_cur,
	.init_ptr_from_cur	= xfs_rmapbt_init_ptr_from_cur,
	.key_diff		= xfs_rmapbt_key_diff,
	.buf_ops		= &xfs_rmapbt_buf_ops,
	.diff_two_keys		= xfs_rmapbt_diff_two_keys,
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

	cur = kmem_zone_zalloc(xfs_btree_cur_zone, KM_NOFS);
	cur->bc_tp = tp;
	cur->bc_mp = mp;
	/* Overlapping btree; 2 keys per pointer. */
	cur->bc_btnum = XFS_BTNUM_RMAP;
	cur->bc_flags = XFS_BTREE_CRC_BLOCKS | XFS_BTREE_OVERLAPPING;
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
		(2 * sizeof(struct xfs_rmap_key) + sizeof(xfs_rmap_ptr_t));
}

/* Compute the maximum height of an rmap btree. */
void
xfs_rmapbt_compute_maxlevels(
	struct xfs_mount		*mp)
{
	if (xfs_sb_version_hasreflink(&mp->m_sb))
		mp->m_rmap_maxlevels = XFS_BTREE_MAXLEVELS;
	else
		mp->m_rmap_maxlevels = xfs_btree_compute_maxlevels(mp,
				mp->m_rmap_mnr, mp->m_sb.sb_agblocks);
}

/* Calculate the refcount btree size for some records. */
xfs_extlen_t
xfs_rmapbt_calc_size(
	struct xfs_mount	*mp,
	unsigned long long	len)
{
	return xfs_btree_calc_size(mp, mp->m_rmap_mnr, len);
}

/*
 * Calculate the maximum refcount btree size.
 */
xfs_extlen_t
xfs_rmapbt_max_size(
	struct xfs_mount	*mp)
{
	/* Bail out if we're uninitialized, which can happen in mkfs. */
	if (mp->m_rmap_mxr[0] == 0)
		return 0;

	return xfs_rmapbt_calc_size(mp, mp->m_sb.sb_agblocks);
}

/*
 * Figure out how many blocks to reserve and how many are used by this btree.
 */
int
xfs_rmapbt_calc_reserves(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno,
	xfs_extlen_t		*ask,
	xfs_extlen_t		*used)
{
	struct xfs_buf		*agbp;
	struct xfs_agf		*agf;
	xfs_extlen_t		pool_len;
	xfs_extlen_t		tree_len;
	int			error;

	if (!xfs_sb_version_hasrmapbt(&mp->m_sb))
		return 0;

	/* Reserve 1% of the AG or enough for 1 block per record. */
	pool_len = max(mp->m_sb.sb_agblocks / 100, xfs_rmapbt_max_size(mp));
	*ask += pool_len;

	error = xfs_alloc_read_agf(mp, NULL, agno, 0, &agbp);
	if (error)
		return error;

	agf = XFS_BUF_TO_AGF(agbp);
	tree_len = be32_to_cpu(agf->agf_rmap_blocks);
	xfs_buf_relse(agbp);

	*used += tree_len;

	return error;
}
