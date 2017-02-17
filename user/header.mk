ifdef TEST_ENV
	include ../build.mk
else
	include build.mk
endif

ifeq ($(UCAFS_SGX), 1)
       FLAGS := -DUCAFS_SGX
endif

ifeq ($(UCAFS_DEV), 1)
       FLAGS += -DUCAFS_DEV -O0 -g
else
       FLAGS += -UUCAFS_DEV -DLOGLEVEL=1 -O2
endif

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS += -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc\
	-fno-builtin-free


CPPFLAGS = $(FLAGS)
CFLAGS = $(FLAGS)
LIBS = -luuid -luv -lmbedcrypto -ltcmalloc

ifeq ($(UCAFS_PROFILER), 1)
       LIBS += -lprofiler
endif

INCFLAGS = -I/usr/local/include

OBJS = uc_dirnode.o\
       uc_filebox.o\
       uc_dirops.o\
       uc_dcache.o\
       uc_metadata.o\
       uc_uspace.o\
       uc_encode.o\
       uc_fetchstore.o\
       uc_supernode.o\
       uc_utils.o\
       uc_vfs.o

GENS := *.a enclave_u.*
