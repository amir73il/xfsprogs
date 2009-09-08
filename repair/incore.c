/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
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
#include "avl.h"
#include "globals.h"
#include "incore.h"
#include "agheader.h"
#include "protos.h"
#include "err_protos.h"
#include "threads.h"

/*
 * push a block allocation record onto list.  assumes list
 * if set to NULL if empty.
 */
void
record_allocation(ba_rec_t *addr, ba_rec_t *list)
{
	addr->next = list;
	list = addr;

	return;
}

void
free_allocations(ba_rec_t *list)
{
	ba_rec_t *current = list;

	while (list != NULL)  {
		list = list->next;
		free(current);
		current = list;
	}

	return;
}

/* ba bmap setupstuff.  setting/getting state is in incore.h  */

void
setup_bmap(xfs_agnumber_t agno, xfs_agblock_t numblocks, xfs_drtbno_t rtblocks)
{
	int i;
	size_t size = 0;

	ba_bmap = (__uint64_t**)malloc(agno*sizeof(__uint64_t *));
	if (!ba_bmap)
		do_error(_("couldn't allocate block map pointers\n"));
	ag_locks = malloc(agno * sizeof(pthread_mutex_t));
	if (!ag_locks)
		do_error(_("couldn't allocate block map locks\n"));

	for (i = 0; i < agno; i++)  {
		size = roundup((numblocks+(NBBY/XR_BB)-1) / (NBBY/XR_BB),
		       		sizeof(__uint64_t));

		ba_bmap[i] = (__uint64_t*)memalign(sizeof(__uint64_t), size);
		if (!ba_bmap[i]) {
			do_error(_("couldn't allocate block map, size = %d\n"),
				numblocks);
			return;
		}
		memset(ba_bmap[i], 0, size);
		pthread_mutex_init(&ag_locks[i], NULL);
	}

	if (rtblocks == 0)  {
		rt_ba_bmap = NULL;
		return;
	}

	size = roundup(rtblocks / (NBBY/XR_BB), sizeof(__uint64_t));

	rt_ba_bmap=(__uint64_t*)memalign(sizeof(__uint64_t), size);
	if (!rt_ba_bmap) {
			do_error(
		_("couldn't allocate realtime block map, size = %llu\n"),
				rtblocks);
			return;
	}

	/*
	 * start all real-time as free blocks
	 */
	set_bmap_rt(rtblocks);

	return;
}

/* ARGSUSED */
void
teardown_rt_bmap(xfs_mount_t *mp)
{
	if (rt_ba_bmap != NULL)  {
		free(rt_ba_bmap);
		rt_ba_bmap = NULL;
	}

	return;
}

/* ARGSUSED */
void
teardown_ag_bmap(xfs_mount_t *mp, xfs_agnumber_t agno)
{
	ASSERT(ba_bmap[agno] != NULL);

	free(ba_bmap[agno]);
	ba_bmap[agno] = NULL;

	return;
}

/* ARGSUSED */
void
teardown_bmap_finish(xfs_mount_t *mp)
{
	free(ba_bmap);
	ba_bmap = NULL;

	return;
}

void
teardown_bmap(xfs_mount_t *mp)
{
	xfs_agnumber_t i;

	for (i = 0; i < mp->m_sb.sb_agcount; i++)  {
		teardown_ag_bmap(mp, i);
	}

	teardown_rt_bmap(mp);
	teardown_bmap_finish(mp);

	return;
}

/*
 * block map initialization routines -- realtime, log, fs
 */
void
set_bmap_rt(xfs_drtbno_t num)
{
	xfs_drtbno_t j;
	xfs_drtbno_t size;

	/*
	 * for now, initialize all realtime blocks to be free
	 * (state == XR_E_FREE)
	 */
	size = howmany(num / (NBBY/XR_BB), sizeof(__uint64_t));

	for (j = 0; j < size; j++)
		rt_ba_bmap[j] = 0x2222222222222222LL;

	return;
}

void
set_bmap_log(xfs_mount_t *mp)
{
	xfs_dfsbno_t	logend, i;

	if (mp->m_sb.sb_logstart == 0)
		return;

	logend = mp->m_sb.sb_logstart + mp->m_sb.sb_logblocks;

	for (i = mp->m_sb.sb_logstart; i < logend ; i++)  {
		set_bmap(XFS_FSB_TO_AGNO(mp, i),
			 XFS_FSB_TO_AGBNO(mp, i), XR_E_INUSE_FS);
	}

	return;
}

void
set_bmap_fs(xfs_mount_t *mp)
{
	xfs_agnumber_t	i;
	xfs_agblock_t	j;
	xfs_agblock_t	end;

	/*
	 * AG header is 4 sectors
	 */
	end = howmany(4 * mp->m_sb.sb_sectsize, mp->m_sb.sb_blocksize);

	for (i = 0; i < mp->m_sb.sb_agcount; i++)
		for (j = 0; j < end; j++)
			set_bmap(i, j, XR_E_INUSE_FS);

	return;
}

#if 0
void
set_bmap_fs_bt(xfs_mount_t *mp)
{
	xfs_agnumber_t	i;
	xfs_agblock_t	j;
	xfs_agblock_t	begin;
	xfs_agblock_t	end;

	begin = bnobt_root;
	end = inobt_root + 1;

	for (i = 0; i < mp->m_sb.sb_agcount; i++)  {
		/*
		 * account for btree roots
		 */
		for (j = begin; j < end; j++)
			set_bmap(i, j, XR_E_INUSE_FS);
	}

	return;
}
#endif

void
incore_init(xfs_mount_t *mp)
{
	int agcount = mp->m_sb.sb_agcount;
	extern void incore_ino_init(xfs_mount_t *);
	extern void incore_ext_init(xfs_mount_t *);

	/* init block alloc bmap */

	setup_bmap(agcount, mp->m_sb.sb_agblocks, mp->m_sb.sb_rextents);
	incore_ino_init(mp);
	incore_ext_init(mp);

	/* initialize random globals now that we know the fs geometry */

	inodes_per_block = mp->m_sb.sb_inopblock;

	return;
}
