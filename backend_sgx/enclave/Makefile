include ../../build.mk



ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g
else
	CFLAGS += -O2
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
	-Ilibnexus_trusted \
	-I..

CFLAGS  += -nostdinc -fvisibility=hidden -fpie -fPIC -fstack-protector\
           -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC




LDFLAGS += -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
           -Wl,--whole-archive -l$(sgx_trts_lib) -Wl,--no-whole-archive \
           -Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -l$(sgx_svc_lib) -Wl,--end-group \
           -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
           -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
           -Wl,--defsym,__ImageBase=0 \
           -Wl,--version-script=enclave.lds


SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign


crypto_lib := mbedtls/library/libmbedcrypto.a

nexus_trusted_objs := \
	nexus_log.o \
	nexus_hash.o \
	nexus_list.o \
	nexus_lru.o \
	nexus_hashtable.o \
	nexus_mac.o \
	nexus_util.o \
	nexus_key.o \
	nexus_encode.o \
	nexus_uuid.o \
	hashmap.o

trusted_objs := $(foreach o,$(nexus_trusted_objs),libnexus_trusted/$(o))


nexus_ecall_objs := \
	dirs.o \
	files.o \
	volume.o

ecall_objs := $(foreach o,$(nexus_ecall_objs),ecalls/$(o))


objs := nexus_enclave_t.o \
	$(trusted_objs) \
	$(ecall_objs) \
	buffer_layer.o \
	data_buffer.o \
	crypto_buffer.o \
	key_buffer.o \
	raw_buffer.o \
	user.o \
	acl.o \
	dentry.o \
	vfs.o \
	crypto_context.o \
	crypto.o \
	volumekey.o \
	metadata.o \
	dirnode.o \
	bucket.o \
	filenode.o \
	supernode.o \
	main.o


build = \
        @if [ -z "$V" ]; then \
                echo '   [$1]     $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi



private_key := private_key.pem

EDGER8ER = $(SGX_SDK)/bin/x64/sgx_edger8r
edl_src := ../nexus_enclave.edl

all: nexus_enclave.signed.so


%.o: %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDE) -c $<  -o $@)

nexus_enclave_t.c: $(edl_src)
	$(EDGER8ER) --search-path $(SGX_SDK_DIR)/include\
		--trusted --trusted-dir . $(edl_src)


$(private_key):
	openssl genrsa -out $@ -3 3072

libmbedcrypto.a:
	make -C mbedtls/library && cp $(crypto_lib) .

nexus_enclave.so: $(objs) libmbedcrypto.a
	$(call build,LD,$(CC) $^  $(LDFLAGS) -o $@)

nexus_enclave.signed.so: nexus_enclave.so $(private_key)
	$(call build,SIGN,$(SGX_ENCLAVE_SIGNER) sign -key $(private_key)\
		-enclave $< -out $@ -config config.xml)


define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef

cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)


clean:
	rm -rf *.a *.o *.so nexus_enclave_t.* libnexus_trusted/*.o ecalls/*.o


.PHONY: all clean
