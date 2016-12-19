USER_DIR := ../user
OPENAFS_DIR := ~/openafs/src/afs
FILES := ucafs_mod.c\
	ucafs_kern.c\
	ucafs_mod.h\
	ucafs_kern.h\
	ucafs_env.h\
	ucafs_header.h

all: install

ucafs_env.h: $(USER_DIR)/ucafs_env.h
	cp -u $^ $@

ucafs_header.h: $(USER_DIR)/ucafs_header.h
	cp -u $^ $@

install: ucafs_header.h ucafs_env.h
	@cp -u $(FILES) $(OPENAFS_DIR)
	@echo "install: $(FILES)"
