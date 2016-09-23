KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = g++
CC = gcc
CPPFLAGS = -g -O0 -std=c++11
CFLAGS = -g -O0
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -lglog\
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
