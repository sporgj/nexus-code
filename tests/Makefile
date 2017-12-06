nexus_home := ..

LIBNEXUS_PATH := $(nexus_home)/libnexus
LIBNEXUS_LIB := libnexus.a

SGX_BACKEND_PATH := $(nexus_home)/backend_sgx
LIBSGX_BACKEND := backend_sgx.so

METADATA_STORE_PATH := $(nexus_home)/metadata_store
LIBMETADATA_STORE := metadata_store.a

MBEDTLS_PATH := $(nexus_home)/mbedtls-2.6.0/library
MBEDTLS_LIB := libmbedcrypto.a

CFLAGS += -I$(LIBNEXUS_PATH) -I$(METADATA_STORE_PATH)

LIBS := $(LIBNEXUS_PATH)/$(LIBNEXUS_LIB)\
		$(SGX_BACKEND_PATH)/$(LIBSGX_BACKEND)\
		$(METADATA_STORE_PATH)/$(LIBMETADATA_STORE)\
		$(MBEDTLS_PATH)/$(MBEDTLS_LIB) -luuid

tests := test_dirops

all: libs $(tests)

.PHONY: libs
libs:
	make -C $(LIBNEXUS_PATH) DEBUG=1
	make -C $(SGX_BACKEND_PATH) DEBUG=1
	make -C $(METADATA_STORE_PATH) DEBUG=1
	make -C $(MBEDTLS_PATH) DEBUG=1 SHARED=1
	cp $(SGX_BACKEND_PATH)/enclave/nexus_enclave.signed.so .

build = \
	@if [ -z "$V" ]; then \
		echo '    [$1]  $@'; \
		$2; \
	else \
		echo '$2'; \
		$2; \
	fi

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

test_dirops: nx_test_dirops.o unity/unity.o $(LIBS)
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

.PHONY: clean clearvolume

clearvolume: 
	rm -rf dummy-volume/*

clean: clearvolume
	rm -rf *.o $(tests)
