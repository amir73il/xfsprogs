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
#ifndef SCRUB_H_
#define SCRUB_H_

#define DESCR_BUFSZ		256

/*
 * Perform all IO in 8M chunks.  This cannot exceed 65536 sectors
 * because that's the biggest SCSI VERIFY(16) we dare to send.
 */
#define IO_MAX_SIZE		8388608
#define IO_MAX_SECTORS		(IO_MAX_SIZE >> BBSHIFT)

struct scrub_ctx;

struct scrub_ops {
	const char	*name;
	bool (*cleanup)(struct scrub_ctx *ctx);
	bool (*scan_fs)(struct scrub_ctx *ctx);
	bool (*scan_inodes)(struct scrub_ctx *ctx);
	bool (*check_dir)(struct scrub_ctx *ctx, const char *descr, int dir_fd);
	bool (*check_inode)(struct scrub_ctx *ctx, const char *descr, int fd,
			    struct stat64 *sb);
	bool (*scan_extents)(struct scrub_ctx *ctx, const char *descr, int fd,
			     struct stat64 *sb, bool attr_fork);
	bool (*scan_xattrs)(struct scrub_ctx *ctx, const char *descr, int fd);
	bool (*scan_special_xattrs)(struct scrub_ctx *ctx, const char *path);
	bool (*scan_metadata)(struct scrub_ctx *ctx);
	bool (*check_summary)(struct scrub_ctx *ctx);
	bool (*scan_blocks)(struct scrub_ctx *ctx);
	bool (*read_file)(struct scrub_ctx *ctx, const char *descr, int fd,
			  struct stat64 *sb);
	bool (*scan_fs_tree)(struct scrub_ctx *ctx);
};

#define SCRUB_QUIRK_FIEMAP_WORKS		(1 << 0)
#define SCRUB_QUIRK_FIEMAP_ATTR_WORKS		(1 << 1)
#define SCRUB_QUIRK_FIBMAP_WORKS		(1 << 2)
#define SCRUB_QUIRK_IGNORE_STATFS_BLOCKS	(1 << 3)
struct scrub_ctx {
	/* Immutable scrub state. */
	struct scrub_ops	*ops;
	char			*mntpoint;
	int			mnt_fd;
	char			*blkdev;
	struct disk		datadev;
	unsigned int		nr_io_threads;
	char			*mnt_type;
	struct stat64		mnt_sb;
	struct statvfs		mnt_sv;
	struct statfs		mnt_sf;
	void			*readbuf;

	/* Mutable scrub state; use lock. */
	pthread_mutex_t		lock;
	unsigned long		errors_found;
	unsigned long		warnings_found;
	unsigned long		quirks;

	void			*priv;
};

extern bool		verbose;
extern int		debug;
extern bool		scrub_data;
extern long		page_size;

void __str_errno(struct scrub_ctx *, const char *, const char *, int);
void __str_error(struct scrub_ctx *, const char *, const char *, int,
		 const char *, ...);
void __str_warn(struct scrub_ctx *, const char *, const char *, int,
		const char *, ...);
void __str_info(struct scrub_ctx *, const char *, const char *, int,
		const char *, ...);

#define str_errno(ctx, str)		__str_errno(ctx, str, __FILE__, __LINE__)
#define str_error(ctx, str, ...)	__str_error(ctx, str, __FILE__, __LINE__, __VA_ARGS__)
#define str_warn(ctx, str, ...)		__str_warn(ctx, str, __FILE__, __LINE__, __VA_ARGS__)
#define str_info(ctx, str, ...)		__str_info(ctx, str, __FILE__, __LINE__, __VA_ARGS__)
#define dbg_printf(fmt, ...)		{if (debug > 1) {printf(fmt, __VA_ARGS__);}}

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
		(type *)( (char *)__mptr - offsetof(type,member) );})

extern struct scrub_ops	generic_scrub_ops;
extern struct scrub_ops	xfs_scrub_ops;
extern struct scrub_ops	ext2_scrub_ops;
extern struct scrub_ops	ext3_scrub_ops;
extern struct scrub_ops	ext4_scrub_ops;
extern struct scrub_ops	btrfs_scrub_ops;

/* Generic implementations of the ops functions */
bool generic_cleanup(struct scrub_ctx *ctx);
bool generic_scan_fs(struct scrub_ctx *ctx);
bool generic_scan_inodes(struct scrub_ctx *ctx);
bool generic_check_dir(struct scrub_ctx *ctx, const char *descr, int dir_fd);
bool generic_check_inode(struct scrub_ctx *ctx, const char *descr, int fd,
			 struct stat64 *sb);
bool generic_scan_extents(struct scrub_ctx *ctx, const char *descr, int fd,
			  struct stat64 *sb, bool attr_fork);
bool generic_scan_xattrs(struct scrub_ctx *ctx, const char *descr, int fd);
bool generic_scan_special_xattrs(struct scrub_ctx *ctx, const char *path);
bool generic_scan_metadata(struct scrub_ctx *ctx);
bool generic_check_summary(struct scrub_ctx *ctx);
bool generic_read_file(struct scrub_ctx *ctx, const char *descr, int fd,
		       struct stat64 *sb);
bool generic_scan_blocks(struct scrub_ctx *ctx);
bool generic_scan_fs_tree(struct scrub_ctx *ctx);

/* Miscellaneous utility functions */
unsigned int scrub_nproc(struct scrub_ctx *ctx);
bool generic_check_directory(struct scrub_ctx *ctx, const char *descr,
		int *pfd);
bool within_range(struct scrub_ctx *ctx, unsigned long long value,
		unsigned long long desired, unsigned long long diff_threshold,
		unsigned int n, unsigned int d, const char *descr);
double auto_space_units(unsigned long long kilobytes, char **units);
double auto_units(unsigned long long number, char **units);

#ifndef HAVE_SYNCFS
static inline int syncfs(int fd)
{
	sync();
	return 0;
}
#endif

#endif /* SCRUB_H_ */
