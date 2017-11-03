include build.mk

CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 $(INCLUDES) $(App_C_Flags)



objs := nx_enclave_u.o\
	nx_main.o\
	nx_volume.o\
	nx_utils.o\
	nx_dirops.o\
	nx_encode.o

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: libnexus.a

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)


nx_enclave_u.c: enclave/nx_enclave.edl
	@$(SGX_EDGER8R) --untrusted --untrusted-dir ./ $^
	@echo "GEN =>  $@"

nx_enclave_u.o: nx_enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $^"


libnexus.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)



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
	rm -f $(wildcard *.o *.a)
