COMMONPATH = ../user
OPENAFS_PATH = ~/openafs
OPENAFS_SRC = ~/openafs/src
OPENAFS_SRC_AFS = $(OPENAFS_SRC)/afs
CC := gcc
SRC = afsx.h \
      afsx.cs.c \
      ucafs_defs.h \
      ucafs_kern.h \
      ucafs_gens.h \
      ucafs_prototypes.h \
      ucafs_fetch.c \
      ucafs_fbox.c \
      uc_kern_store.c \
      ucafs_dirops.c \
      ucafs_main.c

include $(COMMONPATH)/build.mk
ifeq ($(UCAFS_DEV), 1)
      FLAGS := "\#define UCAFS_DEV"
else
      FLAGS := "\#undef UCAFS_DEV"
endif

RXGEN = $(OPENAFS_SRC)/rxgen/rxgen

INC_FLAGS = #-L/usr/local/include
LIB_FLAGS= -L$(OPENAFS_LIB_PATH)

# libraries for the RX compilation
RXLIBS = -lrx\
	 -llwp

GEN = afsx.cs.c afsx.h ucafs_gens.h ucafs_defs.h

all: afsx.cs.c afsx.h ucafs_defs.h ucafs_gens.h
afsx.cs.c: $(COMMONPATH)/afsx.xg
	$(RXGEN) -A -x -C -o $@ $^

afsx.h: $(COMMONPATH)/afsx.xg ucafs_defs.h
	$(RXGEN) -A -x -h -o $@ $<

ucafs_gens.h: $(COMMONPATH)/build.mk
	echo $(FLAGS) > $@

ucafs_defs.h: $(COMMONPATH)/ucafs_defs.h
	cp -u $< $@

.PHONY: install
install: all
	cp -u $(SRC) $(OPENAFS_SRC_AFS)/

.PHONY: rm
rm:
	rm -f $(GEN)

.PHONY: clean
clean: rm
	cd $(OPENAFS_SRC_AFS) && rm -f $(SRC)


.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch

