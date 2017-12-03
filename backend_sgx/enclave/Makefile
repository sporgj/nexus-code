include ../../build.mk



ifeq ($(DEBUG), 1)
LDFLAGS := -O0 -g
else
LDFLAGS := -O2
endif


ifeq ($(SGX_MODE), SIM)
	sgx_trts_lib    := sgx_trts_sim
	sgx_svc_lib     := sgx_tservice_sim
else ifeq ($(SGX_MODE), HW)
	sgx_trts_lib    := sgx_trts
	sgx_svc_lib     := sgx_tservice
else
        $(error Invalid SGX MODE)
endif


INCLUDE := -I$(SGX_SDK)/include \
	   -I$(SGX_SDK)/include/tlibc \
	   -I$(SGX_SDK)/include/stlport \
	   -Imbedtls/include \
	   -I../../libnexus 

CFLAGS  += -nostdinc -fvisibility=hidden -fpie -fPIC -fstack-protector \
	   -DNEXUS_ENCLAVE   # WTF is this used for?




LDFLAGS += -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
	   -Wl,--whole-archive -l$(sgx_trts_lib) -Wl,--no-whole-archive \
	   -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -l$(sgx_svc_lib) -Wl,--end-group \
	   -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	   -Wl,--defsym,__ImageBase=0 \
	   -Wl,--version-script=enclave.lds


CC := gcc # SGX requires GCC (?)

SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign


crypto_lib := mbedtls/library/libmbedcrypto.a

objs :=  nx_enclave_main.o \
	 nx_enclave_crypto.o \
	 nx_enclave_dirnode.o \
	 nexus_enclave_t.o


build = \
        @if [ -z "$V" ]; then \
                echo '   [$1]     $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi



private_key := prviate_key.pem


all: nexus_enclave.signed.so


%.o: %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDE) -c $<  -o $@)


signing_key: $(private_key)
	openssl genrsa -out $@ -3 3072

libmbedcrypto.a:
	make -C mbedtls/library && cp $(crypto_lib) .

nexus_enclave.so: $(objs) libmbedcrypto.a
	$(call build,LD,$(CC) $^  $(LDFLAGS) -o $@)

nexus_enclave.signed.so: nexus_enclave.so
	$(call build,SIGN,$(SGX_ENCLAVE_SIGNER) sign -key private_key.pem -enclave $< -out $@ -config config.xml)


clean:
	rm -rf *.a *.o *.so nexus_enclave_t.*
	make -C mbedtls/library clean


.PHONY: all clean
