LIBNEXUS_PATH := ../libnexus
LIBNEXUS_LIB := -lnexus

SGX_BACKEND_PATH := ../sgx_backend
LIBSGX_BACKEND := -lsgx_backend

CFLAGS += -I$(LIBNEXUS_PATH)

LIBS := -L$(LIBNEXUS_PATH) $(LIBNEXUS_LIB)\
			-L$(SGX_BACKEND_PATH) $(LIBSGX_BACKEND)

tests := test_dirops

all: $(tests) $(LIBNEXUS_LIB)

.PHONY: nexuslib
nexuslib:
	make -C ../

$(LIBNEXUS_LIB): $(wildcard $(LIBNEXUS_PATH)/*.c)
	make -C $(LIBNEXUS_PATH)

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

test_dirops: nx_test_dirops.o unity/unity.o $(LIBNEXUS_LIB)
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

.PHONY: clean
clean:
	rm *.o $(tests) libnexus.a
