USER_DIR    := ../user
OPENAFS_PATH = ~/openafs
OPENAFS_DIR := ~/openafs/src/afs
VANILLA_DIR := ~/vanilla-openafs/src/afs

FILES :=	ucafs_kern.c         \
		ucafs_kern_dirops.c  \
		ucafs_kern_mod.c     \
		ucafs_kern_fetch.c   \
		ucafs_kern_store.c   \
		ucafs_module.h       \
		ucafs_kern.h         \
		ucafs_header.h


all: install


install: ucafs_header.h #install-vanilla
	@cp -u $(FILES) $(OPENAFS_DIR)
	@echo "install: $(FILES)"

install-vanilla:
	@cp -u ucafs_header.h $(VANILLA_DIR)




.PHONY: diff
diff:
	cd ${OPENAFS_PATH} && git diff > ${PWD}/openafs.afsx.patch


build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi




define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)

