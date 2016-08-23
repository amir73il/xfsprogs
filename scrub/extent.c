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
#include "../repair/avl64.h"
#include "extent.h"

struct extent_tree_node {
	struct avl64node	etn_node;
	uint64_t		etn_start;
	uint64_t		etn_length;
};

static __uint64_t
extent_start(
	struct avl64node	*node)
{
	struct extent_tree_node	*etn;

	etn = container_of(node, struct extent_tree_node, etn_node);
	return etn->etn_start;
}

static __uint64_t
extent_end(
	struct avl64node	*node)
{
	struct extent_tree_node	*etn;

	etn = container_of(node, struct extent_tree_node, etn_node);
	return etn->etn_start + etn->etn_length;
}

static struct avl64ops extent_tree_ops = {
	extent_start,
	extent_end,
};

/* Initialize an extent tree. */
bool
extent_tree_init(
	struct extent_tree		*tree)
{
	tree->et_tree = malloc(sizeof(struct avl64tree_desc));
	if (!tree)
		return false;

	pthread_mutex_init(&tree->et_lock, NULL);
	avl64_init_tree(tree->et_tree, &extent_tree_ops);

	return true;
}

/* Free an extent tree. */
void
extent_tree_free(
	struct extent_tree		*tree)
{
	struct avl64node		*node;
	struct avl64node		*n;
	struct extent_tree_node		*ext;

	if (!tree->et_tree)
		return;

	avl_for_each_safe(tree->et_tree, node, n) {
		ext = container_of(node, struct extent_tree_node, etn_node);
		free(ext);
	}
	free(tree->et_tree);
	tree->et_tree = NULL;
}

/* Create a new extent. */
static struct extent_tree_node *
extent_tree_node_init(
	uint64_t		start,
	uint64_t		len)
{
	struct extent_tree_node	*ext;

	ext = malloc(sizeof(struct extent_tree_node));
	if (!ext)
		return NULL;

	ext->etn_node.avl_nextino = NULL;
	ext->etn_start = start;
	ext->etn_length = len;

	return ext;
}

/* Add an extent. */
static bool
__extent_tree_add(
	struct extent_tree		*tree,
	uint64_t			start,
	uint64_t			length)
{
	struct avl64node		*firstn;
	struct avl64node		*lastn;
	struct avl64node		*pos;
	struct avl64node		*n;
	struct avl64node		*l;
	struct extent_tree_node		*ext;
	uint64_t			new_start;
	uint64_t			new_length;
	struct avl64node		*node;
	bool				res = true;

	/* Find any existing nodes over that range. */
	avl64_findranges(tree->et_tree, start - 1, start + length,
			&firstn, &lastn);

	/* Nothing, just insert a new extent. */
	if (firstn == NULL && lastn == NULL) {
		ext = extent_tree_node_init(start, length);
		if (!ext)
			return false;

		node = avl64_insert(tree->et_tree, &ext->etn_node);
		if (node == NULL) {
			free(ext);
			errno = EEXIST;
			return false;
		}

		return true;
	}

	ASSERT(firstn != NULL && lastn != NULL);
	new_start = start;
	new_length = length;

	avl_for_each_range_safe(pos, n, l, firstn, lastn) {
		ext = container_of(pos, struct extent_tree_node, etn_node);

		/* Bail if the new extent is contained within an old one. */
		if (ext->etn_start <= start && ext->etn_length >= length)
			return res;

		/* Check for overlapping and adjacent extents. */
		if (ext->etn_start + ext->etn_length >= start ||
		    ext->etn_start <= start + length) {
			if (ext->etn_start < start)
				new_start = ext->etn_start;

			if (ext->etn_start + ext->etn_length >
			    new_start + new_length)
				new_length = ext->etn_start + ext->etn_length -
						new_start;

			avl64_delete(tree->et_tree, pos);
			free(ext);
		}
	}

	ext = extent_tree_node_init(new_start, new_length);
	if (!ext)
		return false;

	node = avl64_insert(tree->et_tree, &ext->etn_node);
	if (node == NULL) {
		free(ext);
		errno = EEXIST;
		return false;
	}

	return res;
}

/* Add an extent. */
bool
extent_tree_add(
	struct extent_tree		*tree,
	uint64_t			start,
	uint64_t			length)
{
	bool				res;

	pthread_mutex_lock(&tree->et_lock);
	res = __extent_tree_add(tree, start, length);
	pthread_mutex_unlock(&tree->et_lock);

	return res;
}

/* Remove an extent. */
bool
extent_tree_remove(
	struct extent_tree		*tree,
	uint64_t			start,
	uint64_t			len)
{
	struct avl64node		*firstn;
	struct avl64node		*lastn;
	struct avl64node		*pos;
	struct avl64node		*n;
	struct avl64node		*l;
	struct extent_tree_node		*ext;
	uint64_t			new_start;
	uint64_t			new_length;
	struct avl64node		*node;
	int				stat;

	pthread_mutex_lock(&tree->et_lock);
	/* Find any existing nodes over that range. */
	avl64_findranges(tree->et_tree, start - 1, start + len - 1,
			&firstn, &lastn);

	/* Nothing, we're done. */
	if (firstn == NULL && lastn == NULL) {
		pthread_mutex_unlock(&tree->et_lock);
		return true;
	}

	ASSERT(firstn != NULL && lastn != NULL);

	/* Delete or truncate everything in sight. */
	avl_for_each_range_safe(pos, n, l, firstn, lastn) {
		ext = container_of(pos, struct extent_tree_node, etn_node);

		stat = 0;
		if (ext->etn_start < start)
			stat |= 1;
		if (ext->etn_start + ext->etn_length > start + len)
			stat |= 2;
		switch (stat) {
		case 0:
			/* Extent totally within range; delete. */
			avl64_delete(tree->et_tree, pos);
			free(ext);
			break;
		case 1:
			/* Extent is left-adjacent; truncate. */
			ext->etn_length = start - ext->etn_start;
			break;
		case 2:
			/* Extent is right-adjacent; move it. */
			ext->etn_length = ext->etn_start + ext->etn_length -
					(start + len);
			ext->etn_start = start + len;
			break;
		case 3:
			/* Extent overlaps both ends. */
			ext->etn_length = start - ext->etn_start;
			new_start = start + len;
			new_length = ext->etn_start + ext->etn_length -
					new_start;

			ext = extent_tree_node_init(new_start, new_length);
			if (!ext)
				return false;

			node = avl64_insert(tree->et_tree, &ext->etn_node);
			if (node == NULL) {
				errno = EEXIST;
				return false;
			}
			break;
		}
	}

	pthread_mutex_unlock(&tree->et_lock);
	return true;
}

/* Iterate an extent tree. */
bool
extent_tree_iterate(
	struct extent_tree		*tree,
	bool				(*fn)(uint64_t, uint64_t, void *),
	void				*arg)
{
	struct avl64node		*node;
	struct extent_tree_node		*ext;
	bool				moveon = true;

	pthread_mutex_lock(&tree->et_lock);
	avl_for_each(tree->et_tree, node) {
		ext = container_of(node, struct extent_tree_node, etn_node);
		moveon = fn(ext->etn_start, ext->etn_length, arg);
		if (!moveon)
			break;
	}
	pthread_mutex_unlock(&tree->et_lock);

	return moveon;
}

/* Do any extents overlap the given one? */
bool
extent_tree_has_extent(
	struct extent_tree		*tree,
	uint64_t			start,
	uint64_t			len)
{
	struct avl64node		*firstn;
	struct avl64node		*lastn;
	bool				res;

	pthread_mutex_lock(&tree->et_lock);
	/* Find any existing nodes over that range. */
	avl64_findranges(tree->et_tree, start - 1, start + len - 1,
			&firstn, &lastn);

	res = firstn != NULL && lastn != NULL;
	pthread_mutex_unlock(&tree->et_lock);

	return res;
}

/* Is it empty? */
bool
extent_tree_empty(
	struct extent_tree		*tree)
{
	return tree->et_tree->avl_firstino == NULL;
}

static bool
merge_helper(
	uint64_t			start,
	uint64_t			length,
	void				*arg)
{
	struct extent_tree		*thistree = arg;

	return __extent_tree_add(thistree, start, length);
}

/* Merge another tree with this one. */
bool
extent_tree_merge(
	struct extent_tree		*thistree,
	struct extent_tree		*tree)
{
	bool				res;

	assert(thistree != tree);

	pthread_mutex_lock(&thistree->et_lock);
	res = extent_tree_iterate(tree, merge_helper, thistree);
	pthread_mutex_unlock(&thistree->et_lock);

	return res;
}

static bool
extent_tree_dump_fn(
	uint64_t			startblock,
	uint64_t			blockcount,
	void				*arg)
{
	printf("%"PRIu64":%"PRIu64"\n", startblock, blockcount);
	return true;
}

/* Dump extent tree. */
void
extent_tree_dump(
	struct extent_tree		*tree)
{
	printf("EXTENT TREE %p\n", tree);
	extent_tree_iterate(tree, extent_tree_dump_fn, NULL);
	printf("EXTENT DUMP DONE\n");
}
