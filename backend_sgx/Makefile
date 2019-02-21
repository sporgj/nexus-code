include ../build.mk


ifeq ($(SGX_MODE), SIM)
	sgx_urts_lib    := sgx_urts_sim
	sgx_uae_lib     := sgx_uae_service_sim
else ifeq ($(SGX_MODE), HW)
	sgx_urts_lib    := sgx_urts
	sgx_uae_lib     := sgx_uae_service
else
        $(error Invalid SGX MODE)
endif




INCLUDES := -I../libnexus \
            -I$(SGX_SDK)/include \
            -I../probes \
            -I../mbedtls-2.6.0/include

CFLAGS   := -W -Wall -Werror \
            -Wno-nonnull -Wno-unused-parameter -Wno-attributes \
            -D_GNU_SOURCE \
            -std=gnu11 -fPIC

ifeq ($(DTRACE_ENABLED), 1)
	CFLAGS += -DDTRACE_ENABLED
endif

# setup debug info
ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g3
else
	CFLAGS += -O2
endif

ifeq ($(TRACE), 1)
	CFLAGS += -finstrument-functions
endif


LDFLAGS  := -L$(SGX_SDK)/lib64  \
            -L../mbedtls-2.6.0/library

libs     := -l$(sgx_urts_lib) \
            -l$(sgx_uae_lib) \
            -lcurl \
            -lpthread

EDGER8ER = $(SGX_SDK)/bin/x64/sgx_edger8r

objs := nexus_enclave_u.o \
	main.o \
	keybuf.o \
	volume_ops.o \
	dir_ops.o \
	file_ops.o \
	user_ops.o \
	instance_ops.o \
	buffer_manager.o \
	io.o \
	quote.o \
	rk_messages.o \
	commander.o \
	ocalls.o


edl_src := nexus_enclave.edl

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi

static_lib :=  backend_sgx.a

all: $(static_lib)
	make -C enclave DEBUG=$(DEBUG)
	@cp $(static_lib) ../build
	@cp enclave/nexus_enclave.signed.so ../build

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@)

nexus_enclave_u.c: $(edl_src)
	$(EDGER8ER) --search-path $(SGX_SDK_DIR)/include --untrusted --untrusted-dir ./ $(edl_src)

.PHONY: libnexus_probes
libnexus_probes:
	make -C ../probes

$(static_lib): libnexus_probes $(objs)
	$(call build,AR,$(AR) rcs $@ $(objs))



define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



clean:
	rm -f $(wildcard *.o *.a *.so) cscope.* nexus_enclave_u.*
	make -C enclave clean


.PHONY: stubs clean backend_sgx.mri
