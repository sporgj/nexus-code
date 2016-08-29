COMMONPATH = ../user
OPENAFS_PATH = ~/openafs
OPENAFS_SRC = ~/openafs/src
OPENAFS_SRC_AFS = $(OPENAFS_SRC)/afs
CC := clang
SRC = afsx.h \
      afsx.cs.c \
      afsx_hdr.h \
      ucafs_fetch.c \
      ucafs_kern.h \
      afs_secure.h \
      afs_secure.c

RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

INC_FLAGS = #-L/usr/local/include
LIB_FLAGS= -L$(OPENAFS_LIB_PATH)

# libraries for the RX compilation
RXLIBS = -lrx\
	 -llwp

all: afsx.cs.c afsx.h
afsx.cs.c: $(COMMONPATH)/afsx.xg
	$(RXGEN) -A -x -C -o $@ $^

afsx.h: $(COMMONPATH)/afsx.xg afsx_hdr.h
	$(RXGEN) -A -x -h -o $@ $<

afsx_hdr.h: $(COMMONPATH)/afsx_hdr.h
	cp -u $^ $@

.PHONY: copy
copy: all
	cp -u $(SRC) $(OPENAFS_SRC_AFS)/

.PHONY: clean
clean:
	cd $(OPENAFS_SRC_AFS) && rm -f $(SRC)


.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch

