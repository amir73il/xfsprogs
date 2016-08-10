/*
 * Copyright (c) 2011 RedHat, Inc.
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
#ifndef __TRACE_H__
#define __TRACE_H__

#define trace_xfs_alloc_exact_done(a)		((void) 0)
#define trace_xfs_alloc_exact_notfound(a)	((void) 0)
#define trace_xfs_alloc_exact_error(a)		((void) 0)
#define trace_xfs_alloc_near_nominleft(a)	((void) 0)
#define trace_xfs_alloc_near_first(a)		((void) 0)
#define trace_xfs_alloc_near_greater(a)		((void) 0)
#define trace_xfs_alloc_near_lesser(a)		((void) 0)
#define trace_xfs_alloc_near_error(a)		((void) 0)
#define trace_xfs_alloc_near_noentry(a)		((void) 0)
#define trace_xfs_alloc_near_busy(a)		((void) 0)
#define trace_xfs_alloc_size_neither(a)		((void) 0)
#define trace_xfs_alloc_size_noentry(a)		((void) 0)
#define trace_xfs_alloc_size_nominleft(a)	((void) 0)
#define trace_xfs_alloc_size_done(a)		((void) 0)
#define trace_xfs_alloc_size_error(a)		((void) 0)
#define trace_xfs_alloc_size_busy(a)		((void) 0)
#define trace_xfs_alloc_small_freelist(a)	((void) 0)
#define trace_xfs_alloc_small_notenough(a)	((void) 0)
#define trace_xfs_alloc_small_done(a)		((void) 0)
#define trace_xfs_alloc_small_error(a)		((void) 0)
#define trace_xfs_alloc_vextent_badargs(a)	((void) 0)
#define trace_xfs_alloc_vextent_nofix(a)	((void) 0)
#define trace_xfs_alloc_vextent_noagbp(a)	((void) 0)
#define trace_xfs_alloc_vextent_loopfailed(a)	((void) 0)
#define trace_xfs_alloc_vextent_allfailed(a)	((void) 0)

#define trace_xfs_log_recover_item_reorder_head(a,b,c,d)	((void) 0)
#define trace_xfs_log_recover_item_reorder_tail(a,b,c,d)	((void) 0)
#define trace_xfs_log_recover_item_add_cont(a,b,c,d)	((void) 0)
#define trace_xfs_log_recover_item_add(a,b,c,d)	((void) 0)

#define trace_xfs_da_btree_corrupt(a,b)		((void) 0)
#define trace_xfs_btree_corrupt(a,b)		((void) 0)
#define trace_xfs_btree_updkeys(a,b,c)		((void) 0)
#define trace_xfs_btree_overlapped_query_range(a,b,c)	((void) 0)

#define trace_xfs_free_extent(a,b,c,d,e,f,g)	((void) 0)
#define trace_xfs_agf(a,b,c,d)			((void) 0)
#define trace_xfs_read_agf(a,b)			((void) 0)
#define trace_xfs_alloc_read_agf(a,b)		((void) 0)
#define trace_xfs_read_agi(a,b)			((void) 0)
#define trace_xfs_ialloc_read_agi(a,b)		((void) 0)
#define trace_xfs_irec_merge_pre(a,b,c,d,e,f)	((void) 0)
#define trace_xfs_irec_merge_post(a,b,c,d)	((void) 0)

#define trace_xfs_iext_insert(a,b,c,d,e)	((void) 0)
#define trace_xfs_iext_remove(a,b,c,d)		((void) 0)

#define trace_xfs_dir2_grow_inode(a,b)		((void) 0)
#define trace_xfs_dir2_shrink_inode(a,b)	((void) 0)

#define trace_xfs_dir2_leaf_to_node(a)	((void) 0)
#define trace_xfs_dir2_leaf_to_block(a)	((void) 0)
#define trace_xfs_dir2_leaf_addname(a)	((void) 0)
#define trace_xfs_dir2_leaf_lookup(a)	((void) 0)
#define trace_xfs_dir2_leaf_removename(a)	((void) 0)
#define trace_xfs_dir2_leaf_replace(a)	((void) 0)

#define trace_xfs_dir2_block_addname(a)	((void) 0)
#define trace_xfs_dir2_block_to_leaf(a)	((void) 0)
#define trace_xfs_dir2_block_to_sf(a)	((void) 0)
#define trace_xfs_dir2_block_lookup(a)	((void) 0)
#define trace_xfs_dir2_block_removename(a)	((void) 0)
#define trace_xfs_dir2_block_replace(a)	((void) 0)

#define trace_xfs_dir2_leafn_add(a,b)	((void) 0)
#define trace_xfs_dir2_leafn_remove(a,b)	((void) 0)
#define trace_xfs_dir2_leafn_moveents(a,b,c,d)	((void) 0)

#define trace_xfs_dir2_node_to_leaf(a)	((void) 0)
#define trace_xfs_dir2_node_addname(a)	((void) 0)
#define trace_xfs_dir2_node_lookup(a)	((void) 0)
#define trace_xfs_dir2_node_removename(a)	((void) 0)
#define trace_xfs_dir2_node_replace(a)	((void) 0)

#define trace_xfs_dir2_sf_to_block(a)	((void) 0)
#define trace_xfs_dir2_sf_addname(a)	((void) 0)
#define trace_xfs_dir2_sf_create(a)	((void) 0)
#define trace_xfs_dir2_sf_lookup(a)	((void) 0)
#define trace_xfs_dir2_sf_removename(a)	((void) 0)
#define trace_xfs_dir2_sf_replace(a)	((void) 0)
#define trace_xfs_dir2_sf_toino4(a)	((void) 0)
#define trace_xfs_dir2_sf_toino8(a)	((void) 0)

#define trace_xfs_da_node_create(a)		((void) 0)
#define trace_xfs_da_split(a)			((void) 0)
#define trace_xfs_attr_leaf_split_before(a)	((void) 0)
#define trace_xfs_attr_leaf_split_after(a)	((void) 0)
#define trace_xfs_da_root_split(a)		((void) 0)
#define trace_xfs_da_node_split(a)		((void) 0)
#define trace_xfs_da_node_rebalance(a)		((void) 0)
#define trace_xfs_da_node_add(a)		((void) 0)
#define trace_xfs_da_join(a)			((void) 0)
#define trace_xfs_da_root_join(a)		((void) 0)
#define trace_xfs_da_node_toosmall(a)		((void) 0)
#define trace_xfs_da_fixhashpath(a)		((void) 0)
#define trace_xfs_da_node_remove(a)		((void) 0)
#define trace_xfs_da_node_unbalance(a)		((void) 0)
#define trace_xfs_da_link_before(a)		((void) 0)
#define trace_xfs_da_link_after(a)		((void) 0)
#define trace_xfs_da_unlink_back(a)		((void) 0)
#define trace_xfs_da_unlink_forward(a)		((void) 0)
#define trace_xfs_da_path_shift(a)		((void) 0)
#define trace_xfs_da_grow_inode(a)		((void) 0)
#define trace_xfs_da_swap_lastblock(a)		((void) 0)
#define trace_xfs_da_shrink_inode(a)		((void) 0)

#define trace_xfs_attr_sf_create(a)		((void) 0)
#define trace_xfs_attr_sf_add(a)		((void) 0)
#define trace_xfs_attr_sf_remove(a)		((void) 0)
#define trace_xfs_attr_sf_lookup(a)		((void) 0)
#define trace_xfs_attr_sf_to_leaf(a)		((void) 0)
#define trace_xfs_attr_leaf_to_sf(a)		((void) 0)
#define trace_xfs_attr_leaf_to_node(a)		((void) 0)
#define trace_xfs_attr_leaf_create(a)		((void) 0)
#define trace_xfs_attr_leaf_split(a)		((void) 0)
#define trace_xfs_attr_leaf_add_old(a)		((void) 0)
#define trace_xfs_attr_leaf_add_new(a)		((void) 0)
#define trace_xfs_attr_leaf_add(a)		((void) 0)
#define trace_xfs_attr_leaf_add_work(a)		((void) 0)
#define trace_xfs_attr_leaf_compact(a)		((void) 0)
#define trace_xfs_attr_leaf_rebalance(a)	((void) 0)
#define trace_xfs_attr_leaf_toosmall(a)		((void) 0)
#define trace_xfs_attr_leaf_remove(a)		((void) 0)
#define trace_xfs_attr_leaf_unbalance(a)	((void) 0)
#define trace_xfs_attr_leaf_lookup(a)		((void) 0)
#define trace_xfs_attr_leaf_clearflag(a)	((void) 0)
#define trace_xfs_attr_leaf_setflag(a)		((void) 0)
#define trace_xfs_attr_leaf_flipflags(a)	((void) 0)

#define trace_xfs_attr_sf_addname(a)		((void) 0)
#define trace_xfs_attr_leaf_addname(a)		((void) 0)
#define trace_xfs_attr_leaf_replace(a)		((void) 0)
#define trace_xfs_attr_leaf_removename(a)	((void) 0)
#define trace_xfs_attr_leaf_get(a)		((void) 0)
#define trace_xfs_attr_node_addname(a)		((void) 0)
#define trace_xfs_attr_node_replace(a)		((void) 0)
#define trace_xfs_attr_node_removename(a)	((void) 0)
#define trace_xfs_attr_fillstate(a)		((void) 0)
#define trace_xfs_attr_refillstate(a)		((void) 0)
#define trace_xfs_attr_node_get(a)		((void) 0)
#define trace_xfs_attr_rmtval_get(a)		((void) 0)
#define trace_xfs_attr_rmtval_set(a)		((void) 0)
#define trace_xfs_attr_rmtval_remove(a)		((void) 0)

#define trace_xfs_bmap_pre_update(a,b,c,d)	((void) 0)
#define trace_xfs_bmap_post_update(a,b,c,d)	((void) 0)
#define trace_xfs_extlist(a,b,c,d)	((void) 0)
#define trace_xfs_bunmap(a,b,c,d,e)	((void) 0)

/* set c = c to avoid unused var warnings */
#define trace_xfs_perag_get(a,b,c,d)	((c) = (c))
#define trace_xfs_perag_get_tag(a,b,c,d) ((c) = (c))
#define trace_xfs_perag_put(a,b,c,d)	((c) = (c))

#define trace_xfs_defer_init(a,b)		((void) 0)
#define trace_xfs_defer_cancel(a,b)		((void) 0)
#define trace_xfs_defer_intake_work(a,b)	((void) 0)
#define trace_xfs_defer_intake_cancel(a,b)	((void) 0)
#define trace_xfs_defer_pending_commit(a,b)	((void) 0)
#define trace_xfs_defer_pending_abort(a,b)	((void) 0)
#define trace_xfs_defer_pending_cancel(a,b)	((void) 0)
#define trace_xfs_defer_pending_finish(a,b)	((void) 0)
#define trace_xfs_defer_trans_abort(a,b)	((void) 0)
#define trace_xfs_defer_trans_roll(a,b)		((void) 0)
#define trace_xfs_defer_trans_roll_error(a,b,c)	((void) 0)
#define trace_xfs_defer_finish(a,b)		((void) 0)
#define trace_xfs_defer_finish_error(a,b,c)	((void) 0)
#define trace_xfs_defer_finish_done(a,b)	((void) 0)

#endif /* __TRACE_H__ */
