KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = g++
CC = gcc
FLAGS := -g -O0
CPPFLAGS = $(FLAGS) -std=c++11
CFLAGS = $(FLAGS)
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -ltcmalloc\
       -luuid
INCFLAGS = -I/usr/local/include

OBJS = dirnode.o\
       dircache.o\
       filebox.o\
       uspace.o\
       encode.o\
       dirops.o\
       fileops.o\
       utils.o\
       slog.o\
       fbox.pb.o\
       dnode.pb.o

TESTS := test_dnode test_dops test_lookup test_crypto\
	   test_dirs
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a 
