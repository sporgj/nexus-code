USER_DIR := ../user
OPENAFS_PATH = ~/openafs
OPENAFS_DIR := ~/openafs/src/afs
FILES := ucafs_mod.c\
	ucafs_kern.c\
	ucafs_store.c\
	ucafs_mod.h\
	ucafs_kern.h\
	ucafs_env.h\
	ucafs_header.h

all: install

install: ucafs_header.h ucafs_env.h
	@cp -u $(FILES) $(OPENAFS_DIR)
	@echo "install: $(FILES)"

.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch
