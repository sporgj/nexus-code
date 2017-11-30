include build.mk

INCLUDES = -I../libnexus $(App_Include_Paths)

CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull\
	 -Wno-unused-parameter -std=gnu11 -fPIC

LIBS = -luuid $(App_Link_Flags) -L/usr/local/lib -lmbedcrypto


objs := nx_enclave_u.o \
	nexus_sgx_backend_ops.o\
	nexus_sgx_backend_main.o


build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: enclave libsgx_backend.so

.PHONY: enclave
enclave:
	make -C enclave

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)

nx_enclave_u.c: enclave/nx_enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

libsgx_backend.so: $(objs)
	$(call build,CC,$(CC) $^ -shared $(LIBS) -o $@)

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
	rm -f $(wildcard *.o *.a *.so) cscope.* nx_enclave_u.*

.PHONY: distclean
distclean: clean
	make -C enclave distclean
