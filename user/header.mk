KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS := -O0 -g
CPPFLAGS = $(FLAGS) -std=c++11
CFLAGS = $(FLAGS)
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -luuid -ltcmalloc
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

TESTS := test_dnode test_dops test_lookup test_crypto
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a libthird.a\
	   enclave_u.*
