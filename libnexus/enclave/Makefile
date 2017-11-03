include ../build.mk

CC=gcc

APP_PATH = ..
OBJS = nx_enclave_main.o

FLAGS := $(Enclave_C_Flags)

.PHONY: all
all: nx_enclave.signed.so

Enclave_C_Flags += -DNEXUS_ENCLAVE  -I../ \

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

nx_enclave_t.c: nx_enclave.edl
	@$(SGX_EDGER8R) --trusted --trusted-dir . $^
	@echo "GEN +> $@"

nx_enclave_t.o: nx_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC => $@"



nx_enclave.so: nx_enclave_t.o $(OBJS)
	@echo $(SIV_OBJS)
	$(CC) $^ -o $@ $(Enclave_Link_Flags) $(FLAGS)
	@echo "LINK => $@"

nx_enclave.signed.so: nx_enclave.so private_key.pem
	@$(SGX_ENCLAVE_SIGNER) sign -key private_key.pem -enclave $< -out $@ -config config.xml
	@echo "SIGN => $@"

.PHONY: clean
clean:
	rm -rf *.so *.o nx_enclave_t.*
