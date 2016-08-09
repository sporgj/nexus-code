COMMONPATH = ../common
OPENAFS_SRC_AFS = ~/openafs/src/afs
CC := clang
SRC = afsx.h \
      afsx.cs.c \
      afs_secure.h \
      afs_secure.c

INC_FLAGS = #-L/usr/local/include
LIB_FLAGS= -L$(OPENAFS_LIB_PATH)

# libraries for the RX compilation
RXLIBS = -lrx\
	 -llwp

all: afsx.cs.c afsx.h
afsx.cs.c: $(COMMONPATH)/afsx.xg
	rxgen -A -x -C -o $@ $^

afsx.h: $(COMMONPATH)/afsx.xg
	rxgen -A -x -h -o $@ $^

.PHONY: copy
copy:
	cp -u $(SRC) $(OPENAFS_SRC_AFS)/

.PHONY: clean
clean:
	cd $(OPENAFS_SRC_AFS) && rm -f $(SRC)
