include header.mk

CC=gcc

APP_PATH = ..
OBJS = uc_sgx_main.o\
	   uc_sgx_xfer.o\
	   uc_sgx_auth.o\
	   elasticarray.o\
	   elasticqueue.o\
	   seqptrmap.o

SIV_SRC := GCM_SIV.c polyval.c enc_msg_x4.c enc_msg_x8.c\
			dec_msg_htable_x6.c key_expands_and_enc.c
GCMSIV_OBJECTS := $(subst .c,.o,$(SIV_SRC))
GCMSIV_SOURCES := $(patsubst %,siv/%,$(SIV_SRC))
FLAGS := $(Enclave_C_Flags) -mpclmul -maes -mavx -w

.PHONY: all
all: enclave.signed.so

Enclave_C_Flags += -DUCPRIV_ENCLAVE -I../mbedtls/include -I../ \

libmbedcrypto.a: ../mbedtls/library/libmbedcrypto.a
	cp $^ $@

%.o: %.cc
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX => $@"

%.o: %.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"

%.o: siv/%.c
	@$(CC) $(FLAGS) -I/usr/lib/gcc/x86_64-linux-gnu/4.9/include/ -c $< -o $@
	@echo "CC => $@"

private_key.pem:
	openssl genrsa -out $@ -3 3072

enclave_t.c: enclave.edl
	@$(SGX_EDGER8R) --trusted --trusted-dir . $^
	@echo "GEN +> $@"

enclave_t.o: enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"



enclave.so: enclave_t.o $(OBJS) libmbedcrypto.a
	@echo $(SIV_OBJS)
	$(CC) $^ -o $@ $(Enclave_Link_Flags) $(FLAGS)
	@echo "LINK => $@"

enclave.signed.so: enclave.so private_key.pem
	@$(SGX_ENCLAVE_SIGNER) sign -key private_key.pem -enclave $< -out $@ -config config.xml
	@echo "SIGN => $@"

.PHONY: clean
clean:
	rm -rf *.so *.o enclave_t.*
