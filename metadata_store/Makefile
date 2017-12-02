
INCLUDES = -I../libnexus

CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC\
		 $(INCLUDES)


LIBS = 


objs :=	nexus_metadata_store.o \
	nexus_util.o \
	nexus_path.o \
	nexus_vfs.o \
	nexus_dentry.o \
	nexus_volume.o \
	nexus_mstore_flat_directory.o \
	base58.o


build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: metadata_store.a

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

metadata_store.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)
	@cp $@ ../build

define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



clean:
	rm -f $(wildcard *.o *.so *.a) cscope.*


.PHONY: clean
