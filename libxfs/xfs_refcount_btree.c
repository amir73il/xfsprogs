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
#include "libxfs_priv.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_btree.h"
#include "xfs_bmap.h"
#include "xfs_refcount_btree.h"
#include "xfs_alloc.h"
#include "xfs_trace.h"
#include "xfs_cksum.h"
#include "xfs_trans.h"
#include "xfs_bit.h"
#include "xfs_rmap.h"

static struct xfs_btree_cur *
xfs_refcountbt_dup_cursor(
	struct xfs_btree_cur	*cur)
{
	return xfs_refcountbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno,
			cur->bc_private.a.dfops);
}

STATIC void
xfs_refcountbt_set_root(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	int			inc)
{
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	xfs_agnumber_t		seqno = be32_to_cpu(agf->agf_seqno);
	struct xfs_perag	*pag = xfs_perag_get(cur->bc_mp, seqno);

	ASSERT(ptr->s != 0);

	agf->agf_refcount_root = ptr->s;
	be32_add_cpu(&agf->agf_refcount_level, inc);
	pag->pagf_refcount_level += inc;
	xfs_perag_put(pag);

	xfs_alloc_log_agf(cur->bc_tp, agbp,
			XFS_AGF_REFCOUNT_ROOT | XFS_AGF_REFCOUNT_LEVEL);
}

STATIC int
xfs_refcountbt_alloc_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*start,
	union xfs_btree_ptr	*new,
	int			*stat)
{
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	struct xfs_alloc_arg	args;		/* block allocation args */
	int			error;		/* error return value */

	memset(&args, 0, sizeof(args));
	args.tp = cur->bc_tp;
	args.mp = cur->bc_mp;
	args.type = XFS_ALLOCTYPE_NEAR_BNO;
	args.fsbno = XFS_AGB_TO_FSB(cur->bc_mp, cur->bc_private.a.agno,
			xfs_refc_block(args.mp));
	args.firstblock = args.fsbno;
	xfs_rmap_ag_owner(&args.oinfo, XFS_RMAP_OWN_REFC);
	args.minlen = args.maxlen = args.prod = 1;

	error = xfs_alloc_vextent(&args);
	if (error)
		goto out_error;
	trace_xfs_refcountbt_alloc_block(cur->bc_mp, cur->bc_private.a.agno,
			args.agbno, 1);
	if (args.fsbno == NULLFSBLOCK) {
		XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
		*stat = 0;
		return 0;
	}
	ASSERT(args.agno == cur->bc_private.a.agno);
	ASSERT(args.len == 1);

	new->s = cpu_to_be32(args.agbno);
	be32_add_cpu(&agf->agf_refcount_blocks, 1);
	xfs_alloc_log_agf(cur->bc_tp, agbp, XFS_AGF_REFCOUNT_BLOCKS);

	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 1;
	return 0;

out_error:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
	return error;
}

STATIC int
xfs_refcountbt_free_block(
	struct xfs_btree_cur	*cur,
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = cur->bc_mp;
	struct xfs_buf		*agbp = cur->bc_private.a.agbp;
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	xfs_fsblock_t		fsbno = XFS_DADDR_TO_FSB(mp, XFS_BUF_ADDR(bp));
	struct xfs_owner_info	oinfo;

	trace_xfs_refcountbt_free_block(cur->bc_mp, cur->bc_private.a.agno,
			XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno), 1);
	xfs_rmap_ag_owner(&oinfo, XFS_RMAP_OWN_REFC);
	be32_add_cpu(&agf->agf_refcount_blocks, -1);
	xfs_alloc_log_agf(cur->bc_tp, agbp, XFS_AGF_REFCOUNT_BLOCKS);
	xfs_bmap_add_free(mp, cur->bc_private.a.dfops, fsbno, 1,
			&oinfo);

	return 0;
}

STATIC int
xfs_refcountbt_get_minrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_refc_mnr[level != 0];
}

STATIC int
xfs_refcountbt_get_maxrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_refc_mxr[level != 0];
}

STATIC void
xfs_refcountbt_init_key_from_rec(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	ASSERT(rec->refc.rc_startblock != 0);

	key->refc.rc_startblock = rec->refc.rc_startblock;
}

STATIC void
xfs_refcountbt_init_rec_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*rec)
{
	ASSERT(cur->bc_rec.rc.rc_startblock != 0);

	rec->refc.rc_startblock = cpu_to_be32(cur->bc_rec.rc.rc_startblock);
	rec->refc.rc_blockcount = cpu_to_be32(cur->bc_rec.rc.rc_blockcount);
	rec->refc.rc_refcount = cpu_to_be32(cur->bc_rec.rc.rc_refcount);
}

STATIC void
xfs_refcountbt_init_ptr_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));
	ASSERT(agf->agf_refcount_root != 0);

	ptr->s = agf->agf_refcount_root;
}

STATIC __int64_t
xfs_refcountbt_key_diff(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*key)
{
	struct xfs_refcount_irec	*rec = &cur->bc_rec.rc;
	struct xfs_refcount_key		*kp = &key->refc;

	return (__int64_t)be32_to_cpu(kp->rc_startblock) - rec->rc_startblock;
}

STATIC bool
xfs_refcountbt_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_btree_block	*block = XFS_BUF_TO_BLOCK(bp);
	struct xfs_perag	*pag = bp->b_pag;
	unsigned int		level;

	if (block->bb_magic != cpu_to_be32(XFS_REFC_CRC_MAGIC))
		return false;

	if (!xfs_sb_version_hasreflink(&mp->m_sb))
		return false;
	if (!xfs_btree_sblock_v5hdr_verify(bp))
		return false;

	level = be16_to_cpu(block->bb_level);
	if (pag && pag->pagf_init) {
		if (level >= pag->pagf_refcount_level)
			return false;
	} else if (level >= mp->m_refc_maxlevels)
		return false;

	return xfs_btree_sblock_verify(bp, mp->m_refc_mxr[level != 0]);
}

STATIC void
xfs_refcountbt_read_verify(
	struct xfs_buf	*bp)
{
	if (!xfs_btree_sblock_verify_crc(bp))
		xfs_buf_ioerror(bp, -EFSBADCRC);
	else if (!xfs_refcountbt_verify(bp))
		xfs_buf_ioerror(bp, -EFSCORRUPTED);

	if (bp->b_error) {
		trace_xfs_btree_corrupt(bp, _RET_IP_);
		xfs_verifier_error(bp);
	}
}

STATIC void
xfs_refcountbt_write_verify(
	struct xfs_buf	*bp)
{
	if (!xfs_refcountbt_verify(bp)) {
		trace_xfs_btree_corrupt(bp, _RET_IP_);
		xfs_buf_ioerror(bp, -EFSCORRUPTED);
		xfs_verifier_error(bp);
		return;
	}
	xfs_btree_sblock_calc_crc(bp);

}

const struct xfs_buf_ops xfs_refcountbt_buf_ops = {
	.name			= "xfs_refcountbt",
	.verify_read		= xfs_refcountbt_read_verify,
	.verify_write		= xfs_refcountbt_write_verify,
};

#if defined(DEBUG) || defined(XFS_WARN)
STATIC int
xfs_refcountbt_keys_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*k1,
	union xfs_btree_key	*k2)
{
	return be32_to_cpu(k1->refc.rc_startblock) <
	       be32_to_cpu(k2->refc.rc_startblock);
}

STATIC int
xfs_refcountbt_recs_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*r1,
	union xfs_btree_rec	*r2)
{
	struct xfs_refcount_irec	a, b;

	int ret = be32_to_cpu(r1->refc.rc_startblock) +
		be32_to_cpu(r1->refc.rc_blockcount) <=
		be32_to_cpu(r2->refc.rc_startblock);
	if (!ret) {
		a.rc_startblock = be32_to_cpu(r1->refc.rc_startblock);
		a.rc_blockcount = be32_to_cpu(r1->refc.rc_blockcount);
		a.rc_refcount = be32_to_cpu(r1->refc.rc_refcount);
		b.rc_startblock = be32_to_cpu(r2->refc.rc_startblock);
		b.rc_blockcount = be32_to_cpu(r2->refc.rc_blockcount);
		b.rc_refcount = be32_to_cpu(r2->refc.rc_refcount);
		trace_xfs_refcount_rec_order_error(cur->bc_mp,
				cur->bc_private.a.agno, &a, &b);
	}

	return ret;
}
#endif	/* DEBUG */

static const struct xfs_btree_ops xfs_refcountbt_ops = {
	.rec_len		= sizeof(struct xfs_refcount_rec),
	.key_len		= sizeof(struct xfs_refcount_key),

	.dup_cursor		= xfs_refcountbt_dup_cursor,
	.set_root		= xfs_refcountbt_set_root,
	.alloc_block		= xfs_refcountbt_alloc_block,
	.free_block		= xfs_refcountbt_free_block,
	.get_minrecs		= xfs_refcountbt_get_minrecs,
	.get_maxrecs		= xfs_refcountbt_get_maxrecs,
	.init_key_from_rec	= xfs_refcountbt_init_key_from_rec,
	.init_rec_from_cur	= xfs_refcountbt_init_rec_from_cur,
	.init_ptr_from_cur	= xfs_refcountbt_init_ptr_from_cur,
	.key_diff		= xfs_refcountbt_key_diff,
	.buf_ops		= &xfs_refcountbt_buf_ops,
#if defined(DEBUG) || defined(XFS_WARN)
	.keys_inorder		= xfs_refcountbt_keys_inorder,
	.recs_inorder		= xfs_refcountbt_recs_inorder,
#endif
};

/*
 * Allocate a new refcount btree cursor.
 */
struct xfs_btree_cur *
xfs_refcountbt_init_cursor(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp,
	xfs_agnumber_t		agno,
	struct xfs_defer_ops	*dfops)
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	struct xfs_btree_cur	*cur;

	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agno < mp->m_sb.sb_agcount);
	cur = kmem_zone_zalloc(xfs_btree_cur_zone, KM_NOFS);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = XFS_BTNUM_REFC;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_ops = &xfs_refcountbt_ops;

	cur->bc_nlevels = be32_to_cpu(agf->agf_refcount_level);

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;
	cur->bc_private.a.dfops = dfops;
	cur->bc_flags |= XFS_BTREE_CRC_BLOCKS;

	cur->bc_private.a.priv.refc.nr_ops = 0;
	cur->bc_private.a.priv.refc.shape_changes = 0;

	return cur;
}

/*
 * Calculate the number of records in a refcount btree block.
 */
int
xfs_refcountbt_maxrecs(
	struct xfs_mount	*mp,
	int			blocklen,
	bool			leaf)
{
	blocklen -= XFS_REFCOUNT_BLOCK_LEN;

	if (leaf)
		return blocklen / sizeof(struct xfs_refcount_rec);
	return blocklen / (sizeof(struct xfs_refcount_key) +
			   sizeof(xfs_refcount_ptr_t));
}

/* Compute the maximum height of a refcount btree. */
void
xfs_refcountbt_compute_maxlevels(
	struct xfs_mount		*mp)
{
	mp->m_refc_maxlevels = xfs_btree_compute_maxlevels(mp,
			mp->m_refc_mnr, mp->m_sb.sb_agblocks);
}
