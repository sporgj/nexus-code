include ../build.mk




ifeq ($(DEBUG), 1)
LDFLAGS := -O0 -g
else
LDFLAGS := -O2
endif


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
	    -I../mbedtls-2.6.0/include

CFLAGS   := -W -Wall -Werror \
	    -Wno-nonnull -Wno-unused-parameter -Wno-attributes \
	    -D_GNU_SOURCE \
	    -std=gnu11 -fPIC 


LDFLAGS  := -L$(SGX_SDK)/lib64  \
	    -L../mbedtls-2.6.0/library

libs     :=   -l$(sgx_urts_lib) \
	     -l$(sgx_uae_lib) \
	     -lpthread \
	     -luuid

#  -lmbedcrypto \



EDGER8ER = $(SGX_SDK)/bin/x64/sgx_edger8r

objs := nexus_enclave_u.o \
	nexus_sgx_backend_ops.o\
	nexus_sgx_backend_main.o


edl_src := nexus_enclave.edl

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: stubs backend_sgx.so
	make -C enclave/
	@cp backend_sgx.so ../build
	@cp enclave/nexus_enclave.signed.so ..

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@)

stubs: $(edl_src)
	$(EDGER8ER) --search-path $(SGX_SDK_DIR)/include --trusted --trusted-dir ./enclave --untrusted --untrusted-dir ./ $(edl_src)



backend_sgx.so:  $(objs) 
	$(call build,LD,$(CC) $(LDFLAGS) $(objs) $(libs) -shared -o $@)



define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



clean:
	rm -f $(wildcard *.o *.a *.so) cscope.* nx_enclave_u.*
	make -C enclave clean


.PHONY: stubs clean backend_sgx.mri
