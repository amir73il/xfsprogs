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
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#ifdef HAVE_SG_IO
# include <scsi/sg.h>
#endif
#include "disk.h"
#include "scrub.h"

/* Figure out how many disk heads are available. */
unsigned int
disk_heads(
	struct disk		*disk)
{
	int			iomin;
	int			ioopt;
	unsigned short		rot;
	int			error;

	if (getenv("XFS_SCRUB_NO_THREADS"))
		return 1;

	/* If it's not a block device, throw all the CPUs at it. */
	if (!S_ISBLK(disk->d_sb.st_mode))
		return libxfs_nproc();

	/* Non-rotational device?  Throw all the CPUs. */
	rot = 1;
	error = ioctl(disk->d_fd, BLKROTATIONAL, &rot);
	if (error == 0 && rot == 0)
		return libxfs_nproc();

	/*
	 * Sometimes we can infer the number of devices from the
	 * min/optimal IO sizes.
	 */
	iomin = ioopt = 0;
	if (ioctl(disk->d_fd, BLKIOMIN, &iomin) == 0 &&
	    ioctl(disk->d_fd, BLKIOOPT, &ioopt) == 0 &&
            iomin > 0 && ioopt > 0) {
		return ioopt / iomin;
	}

	/* Rotating device?  I guess? */
	return libxfs_nproc() / 2;
}

/* Execute a SCSI VERIFY(16).  We hope. */
#ifdef HAVE_SG_IO
# define SENSE_BUF_LEN		64
# define VERIFY16_CMDLEN	16
# define VERIFY16_CMD		0x8F

# ifndef SG_FLAG_Q_AT_TAIL
#  define SG_FLAG_Q_AT_TAIL	0x10
# endif
int
disk_scsi_verify(
	int			fd,
	uint64_t		startblock, /* lba */
	uint64_t		blockcount) /* lba */
{
	struct sg_io_hdr	iohdr;
	unsigned char		cdb[VERIFY16_CMDLEN];
	unsigned char		sense[SENSE_BUF_LEN];
	uint64_t		llba = startblock;
	uint64_t		veri_len = blockcount;
	int			error;

	/* Borrowed from sg_verify */
	cdb[0] = VERIFY16_CMD;
	cdb[1] = 0; /* skip PI, DPO, and byte check. */
	cdb[2] = (llba >> 56) & 0xff;
	cdb[3] = (llba >> 48) & 0xff;
	cdb[4] = (llba >> 40) & 0xff;
	cdb[5] = (llba >> 32) & 0xff;
	cdb[6] = (llba >> 24) & 0xff;
	cdb[7] = (llba >> 16) & 0xff;
	cdb[8] = (llba >> 8) & 0xff;
	cdb[9] = llba & 0xff;
	cdb[10] = (veri_len >> 24) & 0xff;
	cdb[11] = (veri_len >> 16) & 0xff;
	cdb[12] = (veri_len >> 8) & 0xff;
	cdb[13] = veri_len & 0xff;
	cdb[14] = 0;
	cdb[15] = 0;
	memset(sense, 0, SENSE_BUF_LEN);

	/* v3 SG_IO */
	memset(&iohdr, 0, sizeof(iohdr));
	iohdr.interface_id = 'S';
	iohdr.dxfer_direction = SG_DXFER_NONE;
	iohdr.cmdp = cdb;
	iohdr.cmd_len = VERIFY16_CMDLEN;
	iohdr.sbp = sense;
	iohdr.mx_sb_len = SENSE_BUF_LEN;
	iohdr.flags |= SG_FLAG_Q_AT_TAIL;
	iohdr.timeout = 30000; /* 30s */

	error = ioctl(fd, SG_IO, &iohdr);
	if (error)
		return error;

	dbg_printf("VERIFY(16) fd %d lba %"PRIu64" len %"PRIu64" info %x "
			"status %d masked %d msg %d host %d driver %d "
			"duration %d resid %d\n",
			fd, startblock, blockcount, iohdr.info,
			iohdr.status, iohdr.masked_status, iohdr.msg_status,
			iohdr.host_status, iohdr.driver_status, iohdr.duration,
			iohdr.resid);

	if (iohdr.info & SG_INFO_CHECK) {
		errno = EIO;
		return -1;
	}

	return error;
}
#else
# define disk_scsi_verify(...)		(ENOTTY)
#endif /* HAVE_SG_IO */

/* Test the availability of the kernel scrub ioctl. */
bool
disk_can_scsi_verify(
	int				fd)
{
	int				error;

	if (getenv("XFS_SCRUB_NO_SCSI_VERIFY"))
		return false;

	error = disk_scsi_verify(fd, 0, 1);
	return error == 0;
}

/* Open a disk device and discover its geometry. */
int
disk_open(
	const char		*pathname,
	struct disk		*disk)
{
	int			lba_sz;
	int			error;

	disk->d_fd = open(pathname, O_RDONLY | O_DIRECT | O_NOATIME);
	if (disk->d_fd < 0)
		return -1;
	error = ioctl(disk->d_fd, BLKSSZGET, &lba_sz);
	if (error)
		lba_sz = 512;
	disk->d_lbalog = libxfs_log2_roundup(lba_sz);
	if (disk_can_scsi_verify(disk->d_fd))
		disk->d_flags |= DISK_FLAG_SCSI_VERIFY;
	error = fstat64(disk->d_fd, &disk->d_sb);
	if (error == 0) {
		if (S_ISBLK(disk->d_sb.st_mode)) {
			error = ioctl(disk->d_fd, BLKGETSIZE64,
					&disk->d_nrsectors);
			if (error)
				disk->d_nrsectors = 0;
		} else
			disk->d_nrsectors = disk->d_sb.st_size >> BBSHIFT;
	} else {
		error = errno;
		close(disk->d_fd);
		errno = error;
		disk->d_fd = -1;
		return -1;
	}
	return 0;
}

/* Close a disk device. */
int
disk_close(
	struct disk		*disk)
{
	int			error = 0;

	if (disk->d_fd >= 0)
		error = close(disk->d_fd);
	disk->d_fd = -1;
	return error;
}

/* Is this device open? */
bool
disk_is_open(
	struct disk		*disk)
{
	return disk->d_fd >= 0;
}

/* Read-verify an extent of a disk device. */
ssize_t
disk_read_verify(
	struct disk		*disk,
	void			*buf,
	uint64_t		startblock,
	uint64_t		blockcount)
{
	uint64_t		end = startblock + blockcount;

	/* Convert to logical block size. */
	startblock = startblock >> (disk->d_lbalog - BBSHIFT);
	end = end >> (disk->d_lbalog - BBSHIFT);
	blockcount = end - startblock;
	if (disk->d_flags & DISK_FLAG_SCSI_VERIFY)
		return disk_scsi_verify(disk->d_fd, startblock, blockcount);

	return pread64(disk->d_fd, buf, blockcount << disk->d_lbalog,
			startblock << disk->d_lbalog);
}
