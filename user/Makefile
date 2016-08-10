include header.mk

OPENAFS_PATH := /home/vagrant/openafs
OPENAFS_INC := $(OPENAFS_PATH)/include
OPENAFS_SRC := $(OPENAFS_PATH)/src
OPENAFS_LIB := $(OPENAFS_PATH)/lib

OBJS := req.o afsx.ss.o $(OBJS)
RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

RXINC := -I$(OPENAFS_INC)
RXLIBS := -L$(OPENAFS_LIB) -lrx -llwp

ucafs: main.cc libucafs.a
	$(CXX) $(CPPFLAGS) -I../common $^ $(LIBS) $(RXLIBS) -o $@

afsx.ss.o: afsx.ss.c
	$(CC) $(RXINC) -c $< -o $@

afsx.ss.c: $(COMMON_DIR)/afsx.xg afsx.h
	$(RXGEN) -A -x -S -o $@ $<

afsx.h: $(COMMON_DIR)/afsx.xg
	$(RXGEN) -A -x -h -o $@ $^

libucafs.a: $(OBJS)
	ar cr $@ $^

req.o: req.c afsx.ss.c
	$(CC) $(RXINC) -c $< -o $@

%.o: %.cc %.h
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

dirnode.o: dirnode.cc dirnode.h dnode.pb.cc
	$(CXX) $(CPPFLAGS) $(INCFLAGS) -c $< -o $@

%.pb.cc: %.proto
	protoc --cpp_out=./ $^

.PHONY: clean
clean:
	rm -rf *.pb.h *.pb.cc afsx.h afsx.ss.c $(PROGRAM) $(OBJS) libucafs.a
