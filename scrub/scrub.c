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
#include <stdio.h>
#include <mntent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <dirent.h>
#include "disk.h"
#include "scrub.h"

#define _PATH_PROC_MOUNTS	"/proc/mounts"

bool				verbose;
int				debug;
bool				scrub_data;
bool				dumpcore;
bool				display_rusage;
long				page_size;

static void __attribute__((noreturn))
usage(void)
{
	fprintf(stderr, _("Usage: %s [OPTIONS] mountpoint\n"), progname);
	fprintf(stderr, _("-d:\tRun program in debug mode.\n"));
	fprintf(stderr, _("-t:\tUse this filesystem backend for scrubbing.\n"));
	fprintf(stderr, _("-T:\tDisplay timing/usage information.\n"));
	fprintf(stderr, _("-v:\tVerbose output.\n"));
	fprintf(stderr, _("-x:\tScrub file data too.\n"));

	exit(16);
}

/*
 * Check if the argument is either the device name or mountpoint of a mounted
 * filesystem.
 */
static bool
find_mountpoint_check(
	struct stat64		*sb,
	struct mntent		*t)
{
	struct stat64		ms;

	if (S_ISDIR(sb->st_mode)) {		/* mount point */
		if (stat64(t->mnt_dir, &ms) < 0)
			return false;
		if (sb->st_ino != ms.st_ino)
			return false;
		if (sb->st_dev != ms.st_dev)
			return false;
		/*
		 * Since we can handle non-XFS filesystems, we don't
		 * need to check that the device is accessible.
		 * (The xfs_fsr version of this function does care.)
		 */
	} else {				/* device */
		if (stat64(t->mnt_fsname, &ms) < 0)
			return false;
		if (sb->st_rdev != ms.st_rdev)
			return false;
		/*
		 * Make sure the mountpoint given by mtab is accessible
		 * before using it.
		 */
		if (stat64(t->mnt_dir, &ms) < 0)
			return false;
	}

	return true;
}

/* Check that our alleged mountpoint is in mtab */
static bool
find_mountpoint(
	char			*mtab,
	struct scrub_ctx	*ctx)
{
	struct mntent_cursor	cursor;
	struct mntent		*t = NULL;
	bool			found = false;

	if (platform_mntent_open(&cursor, mtab) != 0) {
		fprintf(stderr, "Error: can't get mntent entries.\n");
		exit(1);
	}

	while ((t = platform_mntent_next(&cursor)) != NULL) {
		/*
		 * Keep jotting down matching mount details; newer mounts are
		 * towards the end of the file (hopefully).
		 */
		if (find_mountpoint_check(&ctx->mnt_sb, t)) {
			ctx->mntpoint = strdup(t->mnt_dir);
			ctx->mnt_type = strdup(t->mnt_type);
			ctx->blkdev = strdup(t->mnt_fsname);
			found = true;
		}
	}
	platform_mntent_close(&cursor);
	return found;
}

/* Print a string and whatever error is stored in errno. */
void
__str_errno(
	struct scrub_ctx	*ctx,
	const char		*str,
	const char		*file,
	int			line)
{
	char			buf[DESCR_BUFSZ];

	pthread_mutex_lock(&ctx->lock);
	fprintf(stderr, "%s: %s.", str, strerror_r(errno, buf, DESCR_BUFSZ));
	if (debug)
		fprintf(stderr, " (%s line %d)", file, line);
	fprintf(stderr, "\n");
	ctx->errors_found++;
	pthread_mutex_unlock(&ctx->lock);
}

/* Print a string and some error text. */
void
__str_error(
	struct scrub_ctx	*ctx,
	const char		*str,
	const char		*file,
	int			line,
	const char		*format,
	...)
{
	va_list			args;

	pthread_mutex_lock(&ctx->lock);
	fprintf(stderr, "%s: ", str);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	if (debug)
		fprintf(stderr, " (%s line %d)", file, line);
	fprintf(stderr, "\n");
	ctx->errors_found++;
	pthread_mutex_unlock(&ctx->lock);
}

/* Print a string and some warning text. */
void
__str_warn(
	struct scrub_ctx	*ctx,
	const char		*str,
	const char		*file,
	int			line,
	const char		*format,
	...)
{
	va_list			args;

	pthread_mutex_lock(&ctx->lock);
	fprintf(stderr, "%s: ", str);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	if (debug)
		fprintf(stderr, " (%s line %d)", file, line);
	fprintf(stderr, "\n");
	ctx->warnings_found++;
	pthread_mutex_unlock(&ctx->lock);
}

/* Print a string and some informational text. */
void
__str_info(
	struct scrub_ctx	*ctx,
	const char		*str,
	const char		*file,
	int			line,
	const char		*format,
	...)
{
	va_list			args;

	pthread_mutex_lock(&ctx->lock);
	fprintf(stderr, "%s: ", str);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	if (debug)
		fprintf(stderr, " (%s line %d)", file, line);
	fprintf(stderr, "\n");
	pthread_mutex_unlock(&ctx->lock);
}

static struct scrub_ops *scrub_impl[] = {
	&xfs_scrub_ops,
	&ext2_scrub_ops,
	&ext3_scrub_ops,
	&ext4_scrub_ops,
	&btrfs_scrub_ops,
	&generic_scrub_ops,
	NULL
};

void __attribute__((noreturn))
do_error(char const *msg, ...)
{
	va_list args;

	fprintf(stderr, _("\nfatal error -- "));

	va_start(args, msg);
	vfprintf(stderr, msg, args);
	if (dumpcore)
		abort();
	exit(1);
}

/* How many threads to kick off? */
unsigned int
scrub_nproc(
	struct scrub_ctx	*ctx)
{
	if (getenv("XFS_SCRUB_NO_THREADS"))
		return 1;
	return ctx->nr_io_threads;
}

/* Decide if a value is within +/- (n/d) of a desired value. */
bool
within_range(
	struct scrub_ctx	*ctx,
	unsigned long long	value,
	unsigned long long	desired,
	unsigned long long	diff_threshold,
	unsigned int		n,
	unsigned int		d,
	const char		*descr)
{
	assert(n < d);

	/* Don't complain if difference does not exceed an absolute value. */
	if (value < desired && desired - value < diff_threshold)
		return true;
	if (value > desired && value - desired < diff_threshold)
		return true;

	/* Complain if the difference exceeds a certain percentage. */
	if (value < desired * (d - n) / d) {
		str_warn(ctx, ctx->mntpoint,
_("Found fewer %s than reported"), descr);
		return false;
	}
	if (value > desired * (d + n) / d) {
		str_warn(ctx, ctx->mntpoint,
_("Found more %s than reported"), descr);
		return false;
	}
	return true;
}

static float
timeval_subtract(
	struct timeval		*tv1,
	struct timeval		*tv2)
{
	return ((tv1->tv_sec - tv2->tv_sec) +
		((float) (tv1->tv_usec - tv2->tv_usec)) / 1000000);
}

/* Produce human readable disk space output. */
double
auto_space_units(
	unsigned long long	kilobytes,
	char			**units)
{
	if (kilobytes > 1073741824ULL) {
		*units = "TiB";
		return kilobytes / 1073741824.0;
	} else if (kilobytes > 1048576ULL) {
		*units = "GiB";
		return kilobytes / 1048576.0;
	} else if (kilobytes > 1024ULL) {
		*units = "MiB";
		return kilobytes / 1024.0;
	} else {
		*units = "KiB";
		return kilobytes;
	}
}

/* Produce human readable discrete number output. */
double
auto_units(
	unsigned long long	number,
	char			**units)
{
	if (number > 1000000000000ULL) {
		*units = "T";
		return number / 1000000000000.0;
	} else if (number > 1000000000ULL) {
		*units = "G";
		return number / 1000000000.0;
	} else if (number > 1000000ULL) {
		*units = "M";
		return number / 1000000.0;
	} else if (number > 1000ULL) {
		*units = "K";
		return number / 1000.0;
	} else {
		*units = "";
		return number;
	}
}

struct phase_info {
	struct rusage		ruse;
	struct timeval		time;
	void			*brk_start;
	const char		*tag;
};

/* Start tracking resource usage for a phase. */
static bool
phase_start(
	struct phase_info	*pi,
	const char		*tag,
	const char		*descr)
{
	int			error;

	error = getrusage(RUSAGE_SELF, &pi->ruse);
	if (error) {
		perror(_("getrusage"));
		return false;
	}
	pi->brk_start = sbrk(0);

	error = gettimeofday(&pi->time, NULL);
	if (error) {
		perror(_("gettimeofday"));
		return false;
	}
	pi->tag = tag;

	if ((verbose || display_rusage) && descr)
		printf(_("%s%s\n"), pi->tag, descr);
	return true;
}

/* Report usage stats. */
static bool
phase_end(
	struct phase_info	*pi)
{
	struct rusage		ruse_now;
#ifdef HAVE_MALLINFO
	struct mallinfo		mall_now;
#endif
	struct timeval		time_now;
	long			iops;
	int			error;

	if (!display_rusage)
		return true;

	error = gettimeofday(&time_now, NULL);
	if (error) {
		perror(_("gettimeofday"));
		return false;
	}

	error = getrusage(RUSAGE_SELF, &ruse_now);
	if (error) {
		perror(_("getrusage"));
		return false;
	}

#define kbytes(x)	(((unsigned long)(x) + 1023) / 1024)
#ifdef HAVE_MALLINFO

	mall_now = mallinfo();
	printf(_("%sMemory used: %luk/%luk (%luk/%luk), "), pi->tag,
		kbytes(mall_now.arena), kbytes(mall_now.hblkhd),
		kbytes(mall_now.uordblks), kbytes(mall_now.fordblks));
#else
	printf(_("%sMemory used: %luk, "), pi->tag,
		(unsigned long) kbytes(((char *) sbrk(0)) -
				       ((char *) pi->brk_start)));
#endif
#undef kbytes

	printf(_("time: %5.2f/%5.2f/%5.2f\n"),
		timeval_subtract(&time_now, &pi->time),
		timeval_subtract(&ruse_now.ru_utime, &pi->ruse.ru_utime),
		timeval_subtract(&ruse_now.ru_stime, &pi->ruse.ru_stime));
	iops =  ruse_now.ru_inblock - pi->ruse.ru_inblock +
		ruse_now.ru_oublock - pi->ruse.ru_oublock;
	printf(_("%sI/O: %lu in/%lu out, rate: %.2f iops\n"), pi->tag,
		ruse_now.ru_inblock - pi->ruse.ru_inblock,
		ruse_now.ru_oublock - pi->ruse.ru_oublock,
		(float)iops / timeval_subtract(&time_now, &pi->time));

	return true;
}

/* Find filesystem geometry and perform any other setup functions. */
static bool
find_geo(
	struct scrub_ctx	*ctx)
{
	bool			moveon;
	int			error;

	ctx->mnt_fd = open(ctx->mntpoint, O_RDONLY | O_NOATIME | O_DIRECTORY);
	if (ctx->mnt_fd < 0) {
		if (errno == EPERM)
			str_error(ctx, ctx->mntpoint,
_("Must be root to run scrub."));
		else
			str_errno(ctx, ctx->mntpoint);
		return false;
	}
	error = disk_open(ctx->blkdev, &ctx->datadev);
	if (error && errno != ENOENT)
		str_errno(ctx, ctx->blkdev);

	error = fstat64(ctx->mnt_fd, &ctx->mnt_sb);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}
	error = fstatvfs(ctx->mnt_fd, &ctx->mnt_sv);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}
	error = fstatfs(ctx->mnt_fd, &ctx->mnt_sf);
	if (error) {
		str_errno(ctx, ctx->mntpoint);
		return false;
	}
	if (disk_is_open(&ctx->datadev))
		ctx->nr_io_threads = disk_heads(&ctx->datadev);
	else
		ctx->nr_io_threads = libxfs_nproc();
	moveon = ctx->ops->scan_fs(ctx);
	if (verbose)
		printf(_("%s: using %d threads to scrub.\n"),
				ctx->mntpoint, ctx->nr_io_threads);

	return moveon;
}

struct scrub_phase {
	char		*descr;
	bool		(*fn)(struct scrub_ctx *);
};

/* Run all the phases of the scrubber. */
static bool
run_scrub_phases(
	struct scrub_ctx	*ctx)
{
	struct scrub_phase	phases[] = {
		{_("Find filesystem geometry."),   find_geo},
		{_("Check internal metadata."),	   ctx->ops->scan_metadata},
		{_("Scan all inodes."),		   ctx->ops->scan_inodes},
		{_("Check directory structure."),  ctx->ops->scan_fs_tree},
		{_("Verify data file integrity."), ctx->ops->scan_blocks},
		{_("Check summary counters."),	   ctx->ops->check_summary},
		{NULL, NULL, NULL},
	};
	struct phase_info	pi;
	char			buf[DESCR_BUFSZ];
	struct scrub_phase	*phase;
	bool			moveon;
	int			c;

	/* Run all phases of the scrub tool. */
	for (c = 1, phase = phases; phase->descr; phase++, c++) {
		snprintf(buf, DESCR_BUFSZ, _("Phase %d: "), c);
		moveon = phase_start(&pi, buf, phase->descr);
		if (!moveon)
			return false;
		moveon = phase->fn(ctx);
		if (!moveon)
			return false;
		moveon = phase_end(&pi);
		if (!moveon)
			return false;
	}

	return true;
}

int
main(
	int			argc,
	char			**argv)
{
	int			c;
	char			*mtab = NULL;
	struct scrub_ctx	ctx;
	struct phase_info	all_pi;
	bool			ismnt;
	bool			moveon = true;
	int			ret;
	struct scrub_ops	**ops;
	int			error;

	progname = basename(argv[0]);
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	pthread_mutex_init(&ctx.lock, NULL);
	memset(&ctx, 0, sizeof(struct scrub_ctx));
	ctx.datadev.d_fd = -1;
	while ((c = getopt(argc, argv, "dm:Tt:vxV")) != EOF) {
		switch (c) {
		case 'd':
			debug++;
			dumpcore = true;
			break;
		case 'm':
			mtab = optarg;
			break;
		case 't':
			for (ops = scrub_impl; *ops; ops++) {
				if (!strcmp(optarg, (*ops)->name)) {
					ctx.ops = *ops;
					break;
				}
			}
			if (!ctx.ops) {
				fprintf(stderr,
_("Unknown filesystem driver '%s'.\n"),
						optarg);
				return 1;
			}
			break;
		case 'T':
			display_rusage = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'x':
			scrub_data = true;
			break;
		case 'V':
			printf(_("%s version %s\n"), progname, VERSION);
			exit(0);
		case '?':
			/* fall through */
		default:
			usage();
		}
	}

	if (optind != argc - 1)
		usage();

	ctx.mntpoint = argv[optind];
	if (!getenv("XFS_SCRUB_NO_FIEMAP"))
		ctx.quirks |= SCRUB_QUIRK_FIEMAP_WORKS |
			      SCRUB_QUIRK_FIEMAP_ATTR_WORKS;
	if (!getenv("XFS_SCRUB_NO_FIBMAP"))
		ctx.quirks |= SCRUB_QUIRK_FIBMAP_WORKS;

	/* Find the mount record for the passed-in argument. */

	if (stat64(argv[optind], &ctx.mnt_sb) < 0) {
		fprintf(stderr,
			_("%s: could not stat: %s: %s\n"),
			progname, argv[optind], strerror(errno));
		return 16;
	}

	/*
	 * If the user did not specify an explicit mount table, try to use
	 * /proc/mounts if it is available, else /etc/mtab.  We prefer
	 * /proc/mounts because it is kernel controlled, while /etc/mtab
	 * may contain garbage that userspace tools like pam_mounts wrote
	 * into it.
	 */
	if (!mtab) {
		if (access(_PATH_PROC_MOUNTS, R_OK) == 0)
			mtab = _PATH_PROC_MOUNTS;
		else
			mtab = _PATH_MOUNTED;
	}

	ismnt = find_mountpoint(mtab, &ctx);
	if (!ismnt) {
		fprintf(stderr, _("%s: Not a mount point or block device.\n"),
			ctx.mntpoint);
		return 16;
	}

	/* Find an appropriate scrub backend. */
	for (ops = scrub_impl; !ctx.ops && *ops; ops++) {
		if (!strcmp(ctx.mnt_type, (*ops)->name))
			ctx.ops = *ops;
	}
	if (!ctx.ops)
		ctx.ops = &generic_scrub_ops;
	if (verbose)
		printf(_("%s: scrubbing %s filesystem with %s driver.\n"),
			ctx.mntpoint, ctx.mnt_type, ctx.ops->name);

	/* Set up a page-aligned buffer for read verification. */
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		str_errno(&ctx, ctx.mntpoint);
		goto out;
	}

	/* Try to allocate a read buffer if we don't have one. */
	error = posix_memalign((void **)&ctx.readbuf, page_size,
			IO_MAX_SIZE);
	if (error || !ctx.readbuf) {
		str_errno(&ctx, ctx.mntpoint);
		goto out;
	}

	/* Flush everything out to disk before we start. */
	error = syncfs(ctx.mnt_fd);
	if (error) {
		str_errno(&ctx, ctx.mntpoint);
		goto out;
	}

	/* Scrub a filesystem. */
	moveon = phase_start(&all_pi, "", NULL);
	if (!moveon)
		goto out;
	moveon = run_scrub_phases(&ctx);
	if (!moveon)
		goto out;

out:
	ret = 0;
	if (errno || !moveon)
		ret |= 8;

	/* Clean up scan data. */
	moveon = ctx.ops->cleanup(&ctx);
	if (!moveon)
		ret |= 8;

	if (ctx.errors_found && ctx.warnings_found)
		fprintf(stderr,
_("%s: %lu errors and %lu warnings found.  Unmount and run fsck.\n"),
			ctx.mntpoint, ctx.errors_found, ctx.warnings_found);
	else if (ctx.errors_found && ctx.warnings_found == 0)
		fprintf(stderr,
_("%s: %lu errors found.  Unmount and run fsck.\n"),
			ctx.mntpoint, ctx.errors_found);
	else if (ctx.errors_found == 0 && ctx.warnings_found)
		fprintf(stderr,
_("%s: %lu warnings found.\n"),
			ctx.mntpoint, ctx.warnings_found);
	if (ctx.errors_found)
		ret |= 4;
	phase_end(&all_pi);
	close(ctx.mnt_fd);
	disk_close(&ctx.datadev);

	free(ctx.blkdev);
	free(ctx.readbuf);
	free(ctx.mntpoint);
	free(ctx.mnt_type);
	return ret;
}
