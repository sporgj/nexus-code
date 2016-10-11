KERNSRC_PATH = ../kernel

SGX_DEBUG := 1

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS := 
CPPFLAGS = $(FLAGS)
CFLAGS = $(FLAGS)
LIBS = -L/usr/local/lib -lprotobuf -pthread -luuid\
       -ltcmalloc -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc\
       -fno-builtin-free
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
