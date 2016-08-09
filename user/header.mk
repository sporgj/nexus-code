COMMON_DIR = ../common

PROGRAM = ucafs
CXX = clang++
CPPFLAGS = -g -std=c++11
LIBS = -lprotobuf -pthread\
       -Lmbedtls/library -lmbedcrypto\
       -lglog\
       -luuid
INCFLAGS = -Imbedtls/include -I$(COMMON_DIR)

OBJS = filebox.o\
       crypto.o\
       encode.o\
       fbox.pb.o
