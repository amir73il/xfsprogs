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
#include "../../repair/threads.h"
#include "read_verify.h"

#define _PATH_PROC_MOUNTS	"/proc/mounts"

bool				verbose;
int				debug;
bool				scrub_data;
bool				dumpcore;
bool				display_rusage;
long				page_size;
enum errors_action		error_action = ERRORS_CONTINUE;
static unsigned long		max_errors;

static void __attribute__((noreturn))
usage(void)
{
	fprintf(stderr, _("Usage: %s [OPTIONS] mountpoint\n"), progname);
	fprintf(stderr, _("-a:\tStop after this many errors are found.\n"));
	fprintf(stderr, _("-d:\tRun program in debug mode.\n"));
	fprintf(stderr, _("-e:\tWhat to do if errors are found.\n"));
	fprintf(stderr, _("-m:\tPath to /etc/mtab.\n"));
	fprintf(stderr, _("-n:\tDry run.  Do not modify anything.\n"));
	fprintf(stderr, _("-t:\tUse this filesystem backend for scrubbing.\n"));
	fprintf(stderr, _("-T:\tDisplay timing/usage information.\n"));
	fprintf(stderr, _("-v:\tVerbose output.\n"));
	fprintf(stderr, _("-V:\tPrint version.\n"));
	fprintf(stderr, _("-x:\tScrub file data too.\n"));
	fprintf(stderr, _("-y:\tRepair all errors.\n"));

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

/* Too many errors? Bail out. */
bool
xfs_scrub_excessive_errors(
	struct scrub_ctx	*ctx)
{
	bool			ret;

	pthread_mutex_lock(&ctx->lock);
	ret = max_errors > 0 && ctx->errors_found >= max_errors;
	pthread_mutex_unlock(&ctx->lock);

	return ret;
}

/* Get the name of the repair tool. */
const char *
repair_tool(
	struct scrub_ctx	*ctx)
{
	if (ctx->ops->repair_tool)
		return ctx->ops->repair_tool;

	return "fsck";
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
	printf("%s: ", str);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	if (debug)
		printf(" (%s line %d)", file, line);
	printf("\n");
	pthread_mutex_unlock(&ctx->lock);
}

/* Increment the repair count. */
void
__record_repair(
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
	ctx->repairs++;
	pthread_mutex_unlock(&ctx->lock);
}

/* Increment the optimization (preening) count. */
void
__record_preen(
	struct scrub_ctx	*ctx,
	const char		*str,
	const char		*file,
	int			line,
	const char		*format,
	...)
{
	va_list			args;

	pthread_mutex_lock(&ctx->lock);
	if (debug || verbose) {
		printf("%s: ", str);
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
		if (debug)
			printf(" (%s line %d)", file, line);
		printf("\n");
	}
	ctx->preens++;
	pthread_mutex_unlock(&ctx->lock);
}

static struct scrub_ops *scrub_impl[] = {
	&xfs_scrub_ops,
	&btrfs_scrub_ops,
	&shared_block_fs_scrub_ops,
	&unstable_inum_fs_scrub_ops,
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

#define SCRUB_QUIRK_FNS(name, flagname) \
bool \
scrub_has_##name( \
	struct scrub_ctx		*ctx) \
{ \
	return ctx->quirks & SCRUB_QUIRK_##flagname; \
}
SCRUB_QUIRK_FNS(fiemap,		FIEMAP_WORKS)
SCRUB_QUIRK_FNS(fiemap_attr,	FIEMAP_ATTR_WORKS)
SCRUB_QUIRK_FNS(fibmap,		FIBMAP_WORKS)
SCRUB_QUIRK_FNS(shared_blocks,	SHARED_BLOCKS)
SCRUB_QUIRK_FNS(unstable_inums,	UNSTABLE_INUM)

/* How many threads to kick off? */
unsigned int
scrub_nproc(
	struct scrub_ctx	*ctx)
{
	if (debug_tweak_on("XFS_SCRUB_NO_THREADS"))
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

static double
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
	unsigned long long	bytes,
	char			**units)
{
	if (debug > 1)
		goto no_prefix;
	if (bytes > (1ULL << 40)) {
		*units = "TiB";
		return (double)bytes / (1ULL << 40);
	} else if (bytes > (1ULL << 30)) {
		*units = "GiB";
		return (double)bytes / (1ULL << 30);
	} else if (bytes > (1ULL << 20)) {
		*units = "MiB";
		return (double)bytes / (1ULL << 20);
	} else if (bytes > (1ULL << 10)) {
		*units = "KiB";
		return (double)bytes / (1ULL << 10);
	} else {
no_prefix:
		*units = "B";
		return bytes;
	}
}

/* Produce human readable discrete number output. */
double
auto_units(
	unsigned long long	number,
	char			**units)
{
	if (debug > 1)
		goto no_prefix;
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
no_prefix:
		*units = "";
		return number;
	}
}

/*
 * Given a directory fd and (possibly) a dirent, open the file associated
 * with the entry.  If the entry is null, just duplicate the dir_fd.
 */
int
dirent_open(
	int			dir_fd,
	struct dirent		*dirent)
{
	if (!dirent)
		return dup(dir_fd);
	return openat(dir_fd, dirent->d_name,
			O_RDONLY | O_NOATIME | O_NOFOLLOW | O_NOCTTY);
}

#ifndef RUSAGE_BOTH
# define RUSAGE_BOTH		(-2)
#endif

/* Get resource usage for ourselves and all children. */
int
scrub_getrusage(
	struct rusage		*usage)
{
	struct rusage		cusage;
	int			err;

	err = getrusage(RUSAGE_BOTH, usage);
	if (!err)
		return err;

	err = getrusage(RUSAGE_SELF, usage);
	if (err)
		return err;

	err = getrusage(RUSAGE_CHILDREN, &cusage);
	if (err)
		return err;

	usage->ru_minflt += cusage.ru_minflt;
	usage->ru_majflt += cusage.ru_majflt;
	usage->ru_nswap += cusage.ru_nswap;
	usage->ru_inblock += cusage.ru_inblock;
	usage->ru_oublock += cusage.ru_oublock;
	usage->ru_msgsnd += cusage.ru_msgsnd;
	usage->ru_msgrcv += cusage.ru_msgrcv;
	usage->ru_nsignals += cusage.ru_nsignals;
	usage->ru_nvcsw += cusage.ru_nvcsw;
	usage->ru_nivcsw += cusage.ru_nivcsw;
	return 0;
}

struct phase_info {
	struct rusage		ruse;
	struct timeval		time;
	unsigned long long	verified_bytes;
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

	error = scrub_getrusage(&pi->ruse); //getrusage(RUSAGE_SELF, &pi->ruse);
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

	pi->verified_bytes = read_verify_bytes();

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
	double			dt;
	unsigned long long	verified;
	long			in, out;
	long			io;
	double			i, o, t;
	double			din, dout, dtot;
	char			*iu, *ou, *tu, *dinu, *doutu, *dtotu;
	double			v, dv;
	char			*vu, *dvu;
	int			error;

	if (!display_rusage)
		return true;

	error = gettimeofday(&time_now, NULL);
	if (error) {
		perror(_("gettimeofday"));
		return false;
	}
	dt = timeval_subtract(&time_now, &pi->time);

	error = scrub_getrusage(&ruse_now); //getrusage(RUSAGE_SELF, &ruse_now);
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

	printf(_("time: %5.2f/%5.2f/%5.2fs\n"),
		timeval_subtract(&time_now, &pi->time),
		timeval_subtract(&ruse_now.ru_utime, &pi->ruse.ru_utime),
		timeval_subtract(&ruse_now.ru_stime, &pi->ruse.ru_stime));

	/* I/O usage */
	in =  (ruse_now.ru_inblock - pi->ruse.ru_inblock) << BBSHIFT;
	out = (ruse_now.ru_oublock - pi->ruse.ru_oublock) << BBSHIFT;
	io = in + out;
	if (io) {
		i = auto_space_units(in, &iu);
		o = auto_space_units(out, &ou);
		t = auto_space_units(io, &tu);
		din = auto_space_units(in / dt, &dinu);
		dout = auto_space_units(out / dt, &doutu);
		dtot = auto_space_units(io / dt, &dtotu);
		printf(
_("%sI/O: %.1f%s in, %.1f%s out, %.1f%s tot\n"),
			pi->tag, i, iu, o, ou, t, tu);
		printf(
_("%sI/O rate: %.1f%s/s in, %.1f%s/s out, %.1f%s/s tot\n"),
			pi->tag, din, dinu, dout, doutu, dtot, dtotu);
	}

	/* How many bytes were read-verified? */
	verified = read_verify_bytes() - pi->verified_bytes;
	if (verified) {
		v = auto_space_units(verified, &vu);
		dv = auto_space_units(verified / dt, &dvu);
		printf(_("%sVerify: %.1f%s, rate: %.1f%s/s\n"), pi->tag,
			v, vu, dv, dvu);
	}

	return true;
}

/* Find filesystem geometry and perform any other setup functions. */
static bool
find_geo(
	struct scrub_ctx	*ctx)
{
	bool			moveon;
	int			error;

	/*
	 * Open the directory with O_NOATIME.  For mountpoints owned
	 * by root, this should be sufficient to ensure that we have
	 * CAP_SYS_ADMIN, which we probably need to do anything fancy
	 * with the (XFS driver) kernel.
	 */
	ctx->mnt_fd = open(ctx->mntpoint, O_RDONLY | O_NOATIME | O_DIRECTORY);
	if (ctx->mnt_fd < 0) {
		if (errno == EPERM)
			str_info(ctx, ctx->mntpoint,
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

/* Run the preening phase if there are no errors. */
static bool
preen(
	struct scrub_ctx	*ctx)
{
	if (ctx->errors_found) {
		str_info(ctx, ctx->mntpoint,
_("Errors found, please re-run with -y."));
		return true;
	}

	return ctx->ops->preen_fs(ctx);
}

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
#define REPAIR_PHASE	(ARRAY_SIZE(phases) - 2)
		{NULL, NULL}, /* fill this in if we're preening or fixing. */
		{NULL, NULL},
	};
	struct phase_info	pi;
	char			buf[DESCR_BUFSZ];
	struct scrub_phase	*phase;
	bool			moveon;
	int			c;

	/* Phase 7 can be turned into preening or fixing the filesystem. */
	phase = &phases[REPAIR_PHASE];
	if (ctx->mode == SCRUB_MODE_PREEN) {
		phase->descr = _("Preen filesystem.");
		phase->fn = preen;
	} else if (ctx->mode == SCRUB_MODE_REPAIR) {
		phase->descr = _("Repair filesystem.");
		phase->fn = ctx->ops->repair_fs;
	}

	/* Run all phases of the scrub tool. */
	for (c = 1, phase = phases; phase->fn; phase++, c++) {
		if (phase->descr)
			snprintf(buf, DESCR_BUFSZ, _("Phase %d: "), c);
		else
			buf[0] = 0;
		moveon = phase_start(&pi, buf, phase->descr);
		if (!moveon)
			return false;
		moveon = phase->fn(ctx);
		if (!moveon)
			return false;
		moveon = phase_end(&pi);
		if (!moveon)
			return false;

		/* Too many errors? */
		if (xfs_scrub_excessive_errors(ctx))
			return false;
	}

	return true;
}

/* Find an appropriate scrub backend. */
static struct scrub_ops *
find_ops(
	const char		*mnt_type)
{
	struct scrub_ops	**ops;
	struct scrub_ops	*op;
	const char		*p;

	for (ops = scrub_impl; *ops; ops++) {
		op = *ops;
		if (op->aliases) {
			for (p = op->aliases; *p != 0; p += strlen(p) + 1) {
				if (!strcmp(mnt_type, p))
					return op;
			}
		}
		if (!strcmp(mnt_type, op->name))
			return op;
	}

	return &generic_scrub_ops;
}

int
main(
	int			argc,
	char			**argv)
{
	int			c;
	char			*mtab = NULL;
	struct scrub_ctx	ctx = {0};
	struct phase_info	all_pi;
	bool			ismnt;
	bool			moveon = true;
	int			ret;
	int			error;

	progname = basename(argv[0]);
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	pthread_mutex_init(&ctx.lock, NULL);
	ctx.datadev.d_fd = -1;
	ctx.mode = SCRUB_MODE_DEFAULT;
	while ((c = getopt(argc, argv, "a:de:m:nTt:vxVy")) != EOF) {
		switch (c) {
		case 'a':
			max_errors = strtoull(optarg, NULL, 10);
			if (errno) {
				perror("max_errors");
				usage();
			}
			break;
		case 'd':
			debug++;
			dumpcore = true;
			break;
		case 'e':
			if (!strcmp("continue", optarg))
				error_action = ERRORS_CONTINUE;
			else if (!strcmp("shutdown", optarg))
				error_action = ERRORS_SHUTDOWN;
			else
				usage();
			break;
		case 'm':
			mtab = optarg;
			break;
		case 'n':
			if (ctx.mode != SCRUB_MODE_DEFAULT) {
				fprintf(stderr,
_("Only one of the options -n or -y may be specified.\n"));
				return 1;
			}
			ctx.mode = SCRUB_MODE_DRY_RUN;
			break;
		case 't':
			ctx.ops = find_ops(optarg);
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
		case 'y':
			if (ctx.mode != SCRUB_MODE_DEFAULT) {
				fprintf(stderr,
_("Only one of the options -n or -y may be specified.\n"));
				return 1;
			}
			ctx.mode = SCRUB_MODE_REPAIR;
			break;
		case '?':
			/* fall through */
		default:
			usage();
		}
	}

	if (optind != argc - 1)
		usage();

	ctx.mntpoint = argv[optind];
	if (!debug_tweak_on("XFS_SCRUB_NO_FIEMAP"))
		ctx.quirks |= SCRUB_QUIRK_FIEMAP_WORKS |
			      SCRUB_QUIRK_FIEMAP_ATTR_WORKS;
	if (!debug_tweak_on("XFS_SCRUB_NO_FIBMAP"))
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
	if (!ctx.ops)
		ctx.ops = find_ops(ctx.mnt_type);
	if (verbose)
		printf(_("%s: scrubbing %s filesystem with %s driver.\n"),
			ctx.mntpoint, ctx.mnt_type, ctx.ops->name);

	/* Initialize overall phase stats. */
	moveon = phase_start(&all_pi, "", NULL);
	if (!moveon)
		goto out;

	/*
	 * Does our backend support shutting down, if the user
	 * wants errors=shutdown?
	 */
	if (error_action == ERRORS_SHUTDOWN && ctx.ops->shutdown_fs == NULL) {
		fprintf(stderr,
_("%s: %s driver does not support error shutdown!\n"),
			ctx.mntpoint, ctx.ops->name);
		goto out;
	}

	/* Does our backend support preen, if the user so requests? */
	if (ctx.mode == SCRUB_MODE_PREEN && ctx.ops->preen_fs == NULL) {
		fprintf(stderr,
_("%s: %s driver does not support preening filesystem!\n"),
			ctx.mntpoint, ctx.ops->name);
		goto out;
	}

	/* Does our backend support repair, if the user so requests? */
	if (ctx.mode == SCRUB_MODE_REPAIR && ctx.ops->repair_fs == NULL) {
		fprintf(stderr,
_("%s: %s driver does not support repairing filesystem!\n"),
			ctx.mntpoint, ctx.ops->name);
		goto out;
	}

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
	moveon = run_scrub_phases(&ctx);
	if (!moveon)
		goto out;

out:
	if (xfs_scrub_excessive_errors(&ctx))
		str_info(&ctx, ctx.mntpoint, _("Too many errors; aborting."));

	ret = 0;
	if (!moveon)
		ret |= 8;

	/* Clean up scan data. */
	moveon = ctx.ops->cleanup(&ctx);
	if (!moveon)
		ret |= 8;

	if (ctx.errors_found && ctx.warnings_found)
		fprintf(stderr,
_("%s: %lu errors and %lu warnings found.  Unmount and run %s.\n"),
			ctx.mntpoint, ctx.errors_found, ctx.warnings_found,
			repair_tool(&ctx));
	else if (ctx.errors_found && ctx.warnings_found == 0)
		fprintf(stderr,
_("%s: %lu errors found.  Unmount and run %s.\n"),
			ctx.mntpoint, ctx.errors_found, repair_tool(&ctx));
	else if (ctx.errors_found == 0 && ctx.warnings_found)
		fprintf(stderr,
_("%s: %lu warnings found.\n"),
			ctx.mntpoint, ctx.warnings_found);
	if (ctx.errors_found) {
		if (error_action == ERRORS_SHUTDOWN)
			ctx.ops->shutdown_fs(&ctx);
		ret |= 4;
	}
	phase_end(&all_pi);
	close(ctx.mnt_fd);
	disk_close(&ctx.datadev);

	free(ctx.blkdev);
	free(ctx.readbuf);
	free(ctx.mntpoint);
	free(ctx.mnt_type);
	return ret;
}
