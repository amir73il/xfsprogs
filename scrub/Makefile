#
# Copyright (c) 2016 Oracle.  All Rights Reserved.
#

TOPDIR = ..
include $(TOPDIR)/include/builddefs

SCRUB_PREREQS=$(HAVE_FIEMAP)$(HAVE_ATTRIBUTES_H)$(HAVE_ATTRIBUTES_MACROS)$(HAVE_ATTRIBUTES_STRUCTS)$(HAVE_FGETXATTR)$(HAVE_FLISTXATTR)$(HAVE_LLISTXATTR)$(HAVE_OPENAT)$(HAVE_READLINKAT)

ifeq ($(SCRUB_PREREQS),yesyesyesyesyesyesyesyesyes)
LTCOMMAND = xfs_scrub
endif

HFILES = scrub.h ../repair/threads.h xfs_ioctl.h read_verify.h iocmd.h
CFILES = ../repair/avl64.c disk.c bitmap.c generic.c iocmd.c non_xfs.c \
	 read_verify.c scrub.c ../repair/threads.c xfs.c xfs_ioctl.c

LLDLIBS += $(LIBBLKID) $(LIBXFS) $(LIBXCMD) $(LIBUUID) $(LIBRT) $(LIBPTHREAD) $(LIBHANDLE)
LTDEPENDENCIES += $(LIBXFS) $(LIBXCMD) $(LIBHANDLE)
LLDFLAGS = -static-libtool-libs

ifeq ($(HAVE_MALLINFO),yes)
LCFLAGS += -DHAVE_MALLINFO
endif

ifeq ($(HAVE_SG_IO),yes)
LCFLAGS += -DHAVE_SG_IO
endif

ifeq ($(HAVE_HDIO_GETGEO),yes)
LCFLAGS += -DHAVE_HDIO_GETGEO
endif

ifeq ($(HAVE_SYNCFS),yes)
LCFLAGS += -DHAVE_SYNCFS
endif

default: depend $(LTCOMMAND)

include $(BUILDRULES)

install: default
	$(INSTALL) -m 755 -d $(PKG_ROOT_SBIN_DIR)
	$(LTINSTALL) -m 755 $(LTCOMMAND) $(PKG_ROOT_SBIN_DIR)
install-dev:

-include .dep
