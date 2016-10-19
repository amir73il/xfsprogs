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
#include "bitmap.h"

#define avl_for_each_range_safe(pos, n, l, first, last) \
	for (pos = (first), n = pos->avl_nextino, l = (last)->avl_nextino; pos != (l); \
			pos = n, n = pos ? pos->avl_nextino : NULL)

#define avl_for_each_safe(tree, pos, n) \
	for (pos = (tree)->avl_firstino, n = pos ? pos->avl_nextino : NULL; \
			pos != NULL; \
			pos = n, n = pos ? pos->avl_nextino : NULL)

#define avl_for_each(tree, pos) \
	for (pos = (tree)->avl_firstino; pos != NULL; pos = pos->avl_nextino)

struct bitmap_node {
	struct avl64node	btn_node;
	uint64_t		btn_start;
	uint64_t		btn_length;
};

static __uint64_t
extent_start(
	struct avl64node	*node)
{
	struct bitmap_node	*btn;

	btn = container_of(node, struct bitmap_node, btn_node);
	return btn->btn_start;
}

static __uint64_t
extent_end(
	struct avl64node	*node)
{
	struct bitmap_node	*btn;

	btn = container_of(node, struct bitmap_node, btn_node);
	return btn->btn_start + btn->btn_length;
}

static struct avl64ops bitmap_ops = {
	extent_start,
	extent_end,
};

/* Initialize an extent tree. */
bool
bitmap_init(
	struct bitmap		*tree)
{
	tree->bt_tree = malloc(sizeof(struct avl64tree_desc));
	if (!tree->bt_tree)
		return false;

	pthread_mutex_init(&tree->bt_lock, NULL);
	avl64_init_tree(tree->bt_tree, &bitmap_ops);

	return true;
}

/* Free an extent tree. */
void
bitmap_free(
	struct bitmap		*tree)
{
	struct avl64node	*node;
	struct avl64node	*n;
	struct bitmap_node	*ext;

	if (!tree->bt_tree)
		return;

	avl_for_each_safe(tree->bt_tree, node, n) {
		ext = container_of(node, struct bitmap_node, btn_node);
		free(ext);
	}
	free(tree->bt_tree);
	tree->bt_tree = NULL;
}

/* Create a new extent. */
static struct bitmap_node *
bitmap_node_init(
	uint64_t		start,
	uint64_t		len)
{
	struct bitmap_node	*ext;

	ext = malloc(sizeof(struct bitmap_node));
	if (!ext)
		return NULL;

	ext->btn_node.avl_nextino = NULL;
	ext->btn_start = start;
	ext->btn_length = len;

	return ext;
}

/* Add an extent (locked). */
static bool
__bitmap_add(
	struct bitmap		*tree,
	uint64_t		start,
	uint64_t		length)
{
	struct avl64node	*firstn;
	struct avl64node	*lastn;
	struct avl64node	*pos;
	struct avl64node	*n;
	struct avl64node	*l;
	struct bitmap_node	*ext;
	uint64_t		new_start;
	uint64_t		new_length;
	struct avl64node	*node;
	bool			res = true;

	/* Find any existing nodes adjacent or within that range. */
	avl64_findranges(tree->bt_tree, start - 1, start + length + 1,
			&firstn, &lastn);

	/* Nothing, just insert a new extent. */
	if (firstn == NULL && lastn == NULL) {
		ext = bitmap_node_init(start, length);
		if (!ext)
			return false;

		node = avl64_insert(tree->bt_tree, &ext->btn_node);
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
		ext = container_of(pos, struct bitmap_node, btn_node);

		/* Bail if the new extent is contained within an old one. */
		if (ext->btn_start <= start &&
		    ext->btn_start + ext->btn_length >= start + length)
			return res;

		/* Check for overlapping and adjacent extents. */
		if (ext->btn_start + ext->btn_length >= start ||
		    ext->btn_start <= start + length) {
			if (ext->btn_start < start) {
				new_start = ext->btn_start;
				new_length += ext->btn_length;
			}

			if (ext->btn_start + ext->btn_length >
			    new_start + new_length)
				new_length = ext->btn_start + ext->btn_length -
						new_start;

			avl64_delete(tree->bt_tree, pos);
			free(ext);
		}
	}

	ext = bitmap_node_init(new_start, new_length);
	if (!ext)
		return false;

	node = avl64_insert(tree->bt_tree, &ext->btn_node);
	if (node == NULL) {
		free(ext);
		errno = EEXIST;
		return false;
	}

	return res;
}

/* Add an extent. */
bool
bitmap_add(
	struct bitmap		*tree,
	uint64_t		start,
	uint64_t		length)
{
	bool			res;

	pthread_mutex_lock(&tree->bt_lock);
	res = __bitmap_add(tree, start, length);
	pthread_mutex_unlock(&tree->bt_lock);

	return res;
}

/* Remove an extent. */
bool
bitmap_remove(
	struct bitmap		*tree,
	uint64_t		start,
	uint64_t		len)
{
	struct avl64node	*firstn;
	struct avl64node	*lastn;
	struct avl64node	*pos;
	struct avl64node	*n;
	struct avl64node	*l;
	struct bitmap_node	*ext;
	uint64_t		new_start;
	uint64_t		new_length;
	struct avl64node	*node;
	int			stat;

	pthread_mutex_lock(&tree->bt_lock);
	/* Find any existing nodes over that range. */
	avl64_findranges(tree->bt_tree, start, start + len, &firstn, &lastn);

	/* Nothing, we're done. */
	if (firstn == NULL && lastn == NULL) {
		pthread_mutex_unlock(&tree->bt_lock);
		return true;
	}

	ASSERT(firstn != NULL && lastn != NULL);

	/* Delete or truncate everything in sight. */
	avl_for_each_range_safe(pos, n, l, firstn, lastn) {
		ext = container_of(pos, struct bitmap_node, btn_node);

		stat = 0;
		if (ext->btn_start < start)
			stat |= 1;
		if (ext->btn_start + ext->btn_length > start + len)
			stat |= 2;
		switch (stat) {
		case 0:
			/* Extent totally within range; delete. */
			avl64_delete(tree->bt_tree, pos);
			free(ext);
			break;
		case 1:
			/* Extent is left-adjacent; truncate. */
			ext->btn_length = start - ext->btn_start;
			break;
		case 2:
			/* Extent is right-adjacent; move it. */
			ext->btn_length = ext->btn_start + ext->btn_length -
					(start + len);
			ext->btn_start = start + len;
			break;
		case 3:
			/* Extent overlaps both ends. */
			ext->btn_length = start - ext->btn_start;
			new_start = start + len;
			new_length = ext->btn_start + ext->btn_length -
					new_start;

			ext = bitmap_node_init(new_start, new_length);
			if (!ext)
				return false;

			node = avl64_insert(tree->bt_tree, &ext->btn_node);
			if (node == NULL) {
				errno = EEXIST;
				return false;
			}
			break;
		}
	}

	pthread_mutex_unlock(&tree->bt_lock);
	return true;
}

/* Iterate an extent tree. */
bool
bitmap_iterate(
	struct bitmap		*tree,
	bool			(*fn)(uint64_t, uint64_t, void *),
	void			*arg)
{
	struct avl64node	*node;
	struct bitmap_node	*ext;
	bool			moveon = true;

	pthread_mutex_lock(&tree->bt_lock);
	avl_for_each(tree->bt_tree, node) {
		ext = container_of(node, struct bitmap_node, btn_node);
		moveon = fn(ext->btn_start, ext->btn_length, arg);
		if (!moveon)
			break;
	}
	pthread_mutex_unlock(&tree->bt_lock);

	return moveon;
}

/* Do any extents overlap the given one?  (locked) */
static bool
__bitmap_has_extent(
	struct bitmap		*tree,
	uint64_t		start,
	uint64_t		len)
{
	struct avl64node	*firstn;
	struct avl64node	*lastn;

	/* Find any existing nodes over that range. */
	avl64_findranges(tree->bt_tree, start, start + len, &firstn, &lastn);

	return firstn != NULL && lastn != NULL;
}

/* Do any extents overlap the given one? */
bool
bitmap_has_extent(
	struct bitmap		*tree,
	uint64_t		start,
	uint64_t		len)
{
	bool			res;

	pthread_mutex_lock(&tree->bt_lock);
	res = __bitmap_has_extent(tree, start, len);
	pthread_mutex_unlock(&tree->bt_lock);

	return res;
}

/* Ensure that the extent is set, and return the old value. */
bool
bitmap_test_and_set(
	struct bitmap		*tree,
	uint64_t		start,
	bool			*was_set)
{
	bool			res = true;

	pthread_mutex_lock(&tree->bt_lock);
	*was_set = __bitmap_has_extent(tree, start, 1);
	if (!(*was_set))
		res = __bitmap_add(tree, start, 1);
	pthread_mutex_unlock(&tree->bt_lock);

	return res;
}

/* Is it empty? */
bool
bitmap_empty(
	struct bitmap		*tree)
{
	return tree->bt_tree->avl_firstino == NULL;
}

static bool
merge_helper(
	uint64_t		start,
	uint64_t		length,
	void			*arg)
{
	struct bitmap		*thistree = arg;

	return __bitmap_add(thistree, start, length);
}

/* Merge another tree with this one. */
bool
bitmap_merge(
	struct bitmap		*thistree,
	struct bitmap		*tree)
{
	bool			res;

	assert(thistree != tree);

	pthread_mutex_lock(&thistree->bt_lock);
	res = bitmap_iterate(tree, merge_helper, thistree);
	pthread_mutex_unlock(&thistree->bt_lock);

	return res;
}

static bool
bitmap_dump_fn(
	uint64_t		startblock,
	uint64_t		blockcount,
	void			*arg)
{
	printf("%"PRIu64":%"PRIu64"\n", startblock, blockcount);
	return true;
}

/* Dump extent tree. */
void
bitmap_dump(
	struct bitmap		*tree)
{
	printf("BITMAP DUMP %p\n", tree);
	bitmap_iterate(tree, bitmap_dump_fn, NULL);
	printf("BITMAP DUMP DONE\n");
}
