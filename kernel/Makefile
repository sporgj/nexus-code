COMMONPATH = ../user
OPENAFS_PATH = ~/openafs
OPENAFS_SRC = ~/openafs/src
OPENAFS_SRC_AFS = $(OPENAFS_SRC)/afs
CC := clang
SRC = afsx.h \
      afsx.cs.c \
      ucafs_defs.h \
      ucafs_kern.h \
      ucafs_prototypes.h \
      ucafs_get.c \
      ucafs_fetch.c \
      ucafs_store.c \
      ucafs_dirops.c \
      ucafs_dnlc.c \
      ucafs_main.c

RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

INC_FLAGS = #-L/usr/local/include
LIB_FLAGS= -L$(OPENAFS_LIB_PATH)

# libraries for the RX compilation
RXLIBS = -lrx\
	 -llwp

GEN = afsx.cs.c afsx.h

all: afsx.cs.c afsx.h ucafs_defs.h
afsx.cs.c: $(COMMONPATH)/afsx.xg
	$(RXGEN) -A -x -C -o $@ $^

afsx.h: $(COMMONPATH)/afsx.xg ucafs_defs.h
	$(RXGEN) -A -x -h -o $@ $<

ucafs_defs.h: $(COMMONPATH)/ucafs_defs.h
	cp -u $^ $@

.PHONY: install
install: all
	cp -u $(SRC) $(OPENAFS_SRC_AFS)/

.PHONY: rm
rm:
	rm $(GEN)

.PHONY: clean
clean: rm
	cd $(OPENAFS_SRC_AFS) && rm -f $(SRC)


.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch

