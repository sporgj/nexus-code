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
	-I$(LIBGCC_PATH) \
	-Imbedtls/include \
	-Ilibnexus_trusted \
	-I. \
	-I..

CFLAGS  += -nostdinc -w\
	-fvisibility=hidden -fpie -fPIC -fstack-protector -mpclmul -maes -mavx \
	-W -Wall -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC\
	-Werror=implicit-function-declaration




LDFLAGS += -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_SDK)/lib64 \
           -Wl,--whole-archive -lsgx_tswitchless -l$(sgx_trts_lib) -Wl,--no-whole-archive \
           -Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$(sgx_svc_lib) -Wl,--end-group \
           -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
           -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
           -Wl,--defsym,__ImageBase=0 \
           -Wl,--version-script=enclave.lds


SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign


crypto_lib := mbedtls/library/libmbedcrypto.a

SIV_PATH := libnexus_trusted/gcm-siv
gcmsiv_sources := \
	GCM_SIV.c \
	polyval.c \
	enc_msg_x4.c \
	enc_msg_x8.c \
	dec_msg_htable_x6.c \
	key_expands_and_enc.c

_gcmsiv_objects := $(subst .c,.o,$(gcmsiv_sources))
gcmsiv_objs := $(foreach o,$(_gcmsiv_objects),$(SIV_PATH)/$(o))

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
	nexus_heap.o \
	nexus_ringbuf.o \
	nexus_str.o \
	tweetnacl.o \
	hashmap.o

trusted_objs := $(foreach o,$(nexus_trusted_objs),libnexus_trusted/$(o))


lua_dir := abac/datalog-engine/lua
lua_lib := $(lua_dir)/liblua.a

_datalog_engine_objs := \
	loader.o \
	interp.o \
	datalog.o

datalog_engine_objs := $(foreach o,$(_datalog_engine_objs),datalog-engine/$(o))

nexus_abac_objs := \
	$(datalog_engine_objs) \
	db.o \
	fact.o \
	perm.o \
	bouncer.o \
	value.o \
	atom.o \
	system_functions.o \
	boolean_operators.o \
	runtime.o \
	parser_lexer.o \
	rule.o \
	user_profile.o \
	policy_store.o \
	attribute_table.o \
	audit_log.o \
	attribute_space.o

abac_objs := $(foreach o,$(nexus_abac_objs),abac/$(o))


nexus_ecall_objs := \
	instance.o \
	dirs.o \
	files.o \
	users.o \
	abac.o \
	volume.o

ecall_objs := $(foreach o,$(nexus_ecall_objs),ecalls/$(o))


objs := nexus_enclave_t.o \
	$(gcmsiv_objs) \
	$(trusted_objs) \
	$(abac_objs) \
	$(ecall_objs) \
	buffer_layer.o \
	data_buffer.o \
	crypto_buffer.o \
	key_buffer.o \
	raw_buffer.o \
	user.o \
	hardlink_table.o \
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
	file_crypto.o \
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

all: abac/datalog-engine/dl_lua.h nexus_enclave.signed.so


bin2c: ./abac/datalog-engine/bin2c.c
	$(call build,CC,$(CC) $^ -o $@)

abac/datalog-engine/dl_lua.h: abac/datalog-engine/datalog.lua bin2c
	$(call build,BIN2C,./bin2c -n datalog.lua -o $@ $<)

%.o: %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDE) -c $<  -o $@)

nexus_enclave_t.c: $(edl_src) ../nexus_abac.edl
	$(EDGER8ER) --search-path ../ --search-path $(SGX_SDK_DIR)/include\
		--trusted --trusted-dir . $(edl_src)


$(private_key):
	openssl genrsa -out $@ -3 3072

libmbedcrypto.a:
	make -C mbedtls/library && cp $(crypto_lib) .

nexus_enclave.so: $(objs) libmbedcrypto.a $(lua_lib)
	$(call build,LD,$(CC) $^  $(LDFLAGS) -o $@)

nexus_enclave.signed.so: nexus_enclave.so $(private_key)
	$(call build,SIGN,$(SGX_ENCLAVE_SIGNER) sign -key $(private_key)\
		-enclave $< -out $@ -config config.xml)

$(lua_lib):
	make -C $(lua_dir)

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
	rm -rf *.a *.o *.so nexus_enclave_t.* libnexus_trusted/*.o ecalls/*.o bin2c $(abac_objs)

.PHONY: distclean
distclean: clean
	make -C abac/datalog-engine/lua clean
	make -C mbedtls clean


.PHONY: all clean
