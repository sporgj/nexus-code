ifdef TEST_ENV
	include ../build.mk
else
	include build.mk
endif

KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS := #-fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc\
	-fno-builtin-free
CPPFLAGS = $(FLAGS)
CFLAGS = $(FLAGS)
LIBS = -L/usr/local/lib /usr/local/lib/libprotobuf.a -pthread -luuid
INCFLAGS = -I/usr/local/include

OBJS = uc_dirnode.o\
       uc_filebox.o\
       uc_dirops.o\
       uc_dcache.o\
       uc_uspace.o\
       uc_encode.o\
       uc_fileops.o\
       uc_utils.o\
       fbox.pb.o\
       dnode.pb.o

TESTS := test_dirops
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a libthird.a\
	   enclave_u.*
