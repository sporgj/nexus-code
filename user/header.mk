KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS := -g -O0
CPPFLAGS = $(FLAGS) -std=c++11
CFLAGS = $(FLAGS)
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -luuid -ltcmalloc
INCFLAGS = -I/usr/local/include

OBJS = uc_dnode.o\
       uc_dirops.o\
       uc_dcache.o\
       filebox.o\
       uc_uspace.o\
       encode.o\
       fileops.o\
       uc_utils.o\
       slog.o\
       sds.o\
       hashmap.o\
       fbox.pb.o\
       dnode.pb.o

TESTS := test_dnode test_dops test_lookup test_crypto
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a 
