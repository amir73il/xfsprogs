/*
 * Copyright (C) 2016 Oracle.  All Rights Reserved.
 *
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
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

#include <sys/uio.h>
#include <xfs/xfs.h>
#include "command.h"
#include "input.h"
#include "init.h"
#include "io.h"

static cmdinfo_t scrub_cmd;
static cmdinfo_t repair_cmd;

/* These must correspond with XFS_SCRUB_TYPE_ */
struct scrub_descr {
	const char	*name;
	bool		is_ag;
};

static const struct scrub_descr scrubbers[] = {
	{"dummy",	false},
	{"sb",		true},
	{"agf",		true},
	{"agfl",	true},
	{"agi",		true},
	{"bnobt",	true},
	{"cntbt",	true},
	{"inobt",	true},
	{"finobt",	true},
	{"rmapbt",	true},
	{"refcountbt",	true},
	{"inode",	false},
	{"bmapbtd",	false},
	{"bmapbta",	false},
	{"bmapbtc",	false},
	{"directory",	false},
	{"xattr",	false},
	{"symlink",	false},
	{"rtbitmap",	false},
	{"rtsummary",	false},
	{"rtrmapbt",	false},
	{NULL, false},
};

static void
scrub_help(void)
{
	const struct scrub_descr	*d;

	printf(_("\n\
 Scrubs a piece of XFS filesystem metadata.  The first argument is the type\n\
 of metadata to examine.  Allocation group number(s) can be specified to\n\
 restrict the scrub operation to a subset of allocation groups.\n\
 Certain metadata types do not take AG numbers.\n\
\n\
 Example:\n\
 'scrub inobt 3 5 7' - scrubs the inode btree in groups 3, 5, and 7.\n\
\n\
 Known metadata scrub types are:"));
	for (d = scrubbers; d->name; d++)
		printf(" %s", d->name);
	printf("\n");
}

static void
scrub_ioctl(
	int				fd,
	int				type,
	unsigned long long		control)
{
	struct xfs_scrub_metadata	meta;
	int				error;

	memset(&meta, 0, sizeof(meta));
	meta.type = type;
	meta.control = control;
	meta.flags = 0;

	error = ioctl(fd, XFS_IOC_SCRUB_METADATA, &meta);
	if (error)
		perror("scrub");
	if (meta.flags & XFS_SCRUB_FLAG_CORRUPT)
		printf("Corruption detected.");
	if (meta.flags & XFS_SCRUB_FLAG_PREEN)
		printf("Optimization possible.");
	if (meta.flags & XFS_SCRUB_FLAG_XREF_FAIL)
		printf("Cross-referencing failed.");
}

static int
scrub_f(
	int				argc,
	char				**argv)
{
	char				*p;
	int				type = -1;
	int				i, c;
	unsigned long long		control;
	bool				is_ag;
	struct xfs_fsop_geom		geom;
	const struct scrub_descr	*d;

	while ((c = getopt(argc, argv, "")) != EOF) {
		switch (c) {
		default:
			return command_usage(&scrub_cmd);
		}
	}
	if (optind > argc - 1)
		return command_usage(&scrub_cmd);

	for (i = 0, d = scrubbers; d->name; i++, d++) {
		if (strcmp(d->name, argv[optind]) == 0) {
			type = i;
			is_ag = d->is_ag;
		}
	}
	optind++;

	if (type < 0)
		return command_usage(&scrub_cmd);

	if (!is_ag)
		geom.agcount = 1;
	else {
		i = xfsctl(file->name, file->fd, XFS_IOC_FSGEOMETRY_V1, &geom);
		if (i < 0) {
			fprintf(stderr,
				_("%s: can't get geometry [\"%s\"]: %s\n"),
				progname, file->name, strerror(errno));
			exitcode = 1;
			return 0;
		}
	}

	if (optind == argc) {
		for (control = 0; control < geom.agcount; control++)
			scrub_ioctl(file->fd, type, control);
		return 0;
	}

	for (i = optind; i < argc; i++) {
		control = strtoull(argv[i], &p, 0);
		if (*p != '\0') {
			fprintf(stderr,
				_("bad control number %s\n"), argv[i]);
			return 0;
		}

		scrub_ioctl(file->fd, type, control);
	}
	return 0;
}

void
scrub_init(void)
{
	scrub_cmd.name = "scrub";
	scrub_cmd.altname = "sc";
	scrub_cmd.cfunc = scrub_f;
	scrub_cmd.argmin = 1;
	scrub_cmd.argmax = -1;
	scrub_cmd.flags = CMD_NOMAP_OK;
	scrub_cmd.args =
_("type [agno...]");
	scrub_cmd.oneline =
		_("scrubs filesystem metadata");
	scrub_cmd.help = scrub_help;

	add_command(&scrub_cmd);
}

static void
repair_help(void)
{
	const struct scrub_descr	*d;

	printf(_("\n\
 Repairs a piece of XFS filesystem metadata.  The first argument is the type\n\
 of metadata to examine.  Allocation group number(s) can be specified to\n\
 restrict the scrub operation to a subset of allocation groups.\n\
 Certain metadata types do not take AG numbers.\n\
\n\
 Example:\n\
 'repair inobt 3 5 7' - repairs the inode btree in groups 3, 5, and 7.\n\
\n\
 Known metadata repairs types are:"));
	for (d = scrubbers; d->name; d++)
		printf(" %s", d->name);
	printf("\n");
}

static void
repair_ioctl(
	int				fd,
	int				type,
	unsigned long long		control)
{
	struct xfs_scrub_metadata	meta;
	int				error;

	memset(&meta, 0, sizeof(meta));
	meta.type = type;
	meta.control = control;
	meta.flags = XFS_SCRUB_FLAG_REPAIR;

	error = ioctl(fd, XFS_IOC_SCRUB_METADATA, &meta);
	if (error)
		perror("scrub");
	if (meta.flags & XFS_SCRUB_FLAG_CORRUPT)
		printf("Corruption remains.\n");
	if (meta.flags & XFS_SCRUB_FLAG_PREEN)
		printf("Optimization possible.\n");
	if (meta.flags & XFS_SCRUB_FLAG_XREF_FAIL)
		printf("Cross-referencing failed.\n");
}

static int
repair_f(
	int				argc,
	char				**argv)
{
	char				*p;
	int				type = -1;
	int				i, c;
	unsigned long long		control;
	bool				is_ag;
	struct xfs_fsop_geom		geom;
	const struct scrub_descr	*d;

	while ((c = getopt(argc, argv, "")) != EOF) {
		switch (c) {
		default:
			return command_usage(&repair_cmd);
		}
	}
	if (optind > argc - 1)
		return command_usage(&repair_cmd);

	for (i = 0, d = scrubbers; d->name; i++, d++) {
		if (strcmp(d->name, argv[optind]) == 0) {
			type = i;
			is_ag = d->is_ag;
		}
	}
	optind++;

	if (type < 0)
		return command_usage(&repair_cmd);

	if (!is_ag)
		geom.agcount = 1;
	else {
		i = xfsctl(file->name, file->fd, XFS_IOC_FSGEOMETRY_V1, &geom);
		if (i < 0) {
			fprintf(stderr,
				_("%s: can't get geometry [\"%s\"]: %s\n"),
				progname, file->name, strerror(errno));
			exitcode = 1;
			return 0;
		}
	}

	if (optind == argc) {
		for (control = 0; control < geom.agcount; control++)
			repair_ioctl(file->fd, type, control);
		return 0;
	}

	for (i = optind; i < argc; i++) {
		control = strtoull(argv[i], &p, 0);
		if (*p != '\0') {
			fprintf(stderr,
				_("bad control number %s\n"), argv[i]);
			return 0;
		}

		repair_ioctl(file->fd, type, control);
	}
	return 0;
}

void
repair_init(void)
{
	if (!expert)
		return;
	repair_cmd.name = "repair";
	repair_cmd.altname = "fix";
	repair_cmd.cfunc = repair_f;
	repair_cmd.argmin = 1;
	repair_cmd.argmax = -1;
	repair_cmd.flags = CMD_NOMAP_OK;
	repair_cmd.args =
_("type [agno...]");
	repair_cmd.oneline =
		_("repairs filesystem metadata");
	repair_cmd.help = repair_help;

	add_command(&repair_cmd);
}
