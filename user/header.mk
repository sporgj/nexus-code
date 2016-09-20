KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = clang++
CC = clang
CPPFLAGS = -g -O0 -std=c++11
CFLAGS = -g -O0
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -lglog\
       -luuid
INCFLAGS = -I/usr/local/include

OBJS = dirnode.o\
       filebox.o\
       uspace.o\
       encode.o\
       dirops.o\
       fileops.o\
       utils.o\
       fbox.pb.o\
       dnode.pb.o

TESTS := test_dnode test_dops test_lookup test_crypto\
	   test_dirs
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a 
