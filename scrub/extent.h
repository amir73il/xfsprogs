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
#ifndef EXTENT_H_
#define EXTENT_H_

struct extent_tree {
	pthread_mutex_t			et_lock;
	struct avl64tree_desc		*et_tree;
};

#define avl_for_each_range_safe(pos, n, l, first, last) \
	for (pos = (first), n = pos->avl_nextino, l = (last)->avl_nextino; pos != (l); \
			pos = n, n = pos ? pos->avl_nextino : NULL)

#define avl_for_each_safe(tree, pos, n) \
	for (pos = (tree)->avl_firstino, n = pos ? pos->avl_nextino : NULL; \
			pos != NULL; \
			pos = n, n = pos ? pos->avl_nextino : NULL)

#define avl_for_each(tree, pos) \
	for (pos = (tree)->avl_firstino; pos != NULL; pos = pos->avl_nextino)

bool extent_tree_init(struct extent_tree *tree);
void extent_tree_free(struct extent_tree *tree);
bool extent_tree_add(struct extent_tree *tree, uint64_t start, uint64_t length);
bool extent_tree_remove(struct extent_tree *tree, uint64_t start,
		uint64_t len);
bool extent_tree_iterate(struct extent_tree *tree,
		bool (*fn)(uint64_t, uint64_t, void *), void *arg);
bool extent_tree_has_extent(struct extent_tree *tree, uint64_t start,
		uint64_t len);
bool extent_tree_empty(struct extent_tree *tree);
bool extent_tree_merge(struct extent_tree *thistree, struct extent_tree *tree);
void extent_tree_dump(struct extent_tree *tree);

#endif /* EXTENT_H_ */
