USER_DIR := ../user
OPENAFS_PATH = ~/openafs
OPENAFS_DIR := ~/openafs/src/afs
FILES := \
	ucafs_kern.c\
	ucafs_kern_dirops.c\
	ucafs_kern_mod.c\
	ucafs_kern_fetch.c\
	ucafs_kern_store.c\
	ucafs_module.h\
	ucafs_kern.h\
	ucafs_header.h

all: install

install: ucafs_header.h
	@cp -u $(FILES) $(OPENAFS_DIR)
	@echo "install: $(FILES)"

.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch
