include build.mk

MBEDTLS_PATH ?= /usr/local/include/mbedtls/include

INCLUDES += -I$(MBEDTLS_PATH)
CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11\
	 $(INCLUDES) $(App_C_Flags)

LIBS = -lmbedcrypto $(App_Link_Flags) -luuid


objs :=	nx_enclave_u.o \
	nexus_fs_ops.o \
	nexus_json.o \
	nexus_volume.o \
	nexus_encode.o \
	nexus_main.o \
	nexus_vfs.o \
	nexus_dentry.o \
	jsmn.o \
	nexus_util.o 
build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: libnexus.a nexus-admin

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)

nx_enclave_u.c: enclave/nx_enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

libnexus.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)

nexus-admin: nx_admin.o libnexus.a
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



.PHONY: clean
clean:
	rm -f $(wildcard *.o *.a) nexus-admin nx_enclave_u.*
