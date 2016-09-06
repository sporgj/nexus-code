KERNSRC_PATH = ../kernel

PROGRAM = ucafs
CXX = clang++
CC = clang
CPPFLAGS = -g -std=c++11
CFLAGS = -g
LIBS = -L/usr/local/lib -lprotobuf -pthread\
       -Lmbedtls/library -lmbedcrypto\
       -lglog\
       -luuid
INCFLAGS = -Imbedtls/include -I/usr/local/include

OBJS = dirnode.o\
       filebox.o\
       uspace.o\
       encode.o\
       dirops.o\
       fileops.o\
       utils.o\
       dnode.pb.o

TESTS := test_dnode test_dops test_lookup
GENS := afsx.h afsx.cs.c afsx.ss.c *.pb.h *.pb.cc libucafs.a 
