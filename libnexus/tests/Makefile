include ../build.mk

CFLAGS += -I../ $(App_C_Flags)

LIBS := -lmbedcrypto $(App_Link_Flags) -luuid

tests := test_dirnode

all: $(tests)

.PHONY: nexuslib
nexuslib:
	make -C ../

libnexus.a: ../libnexus.a
	cp $^ $@

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

test_dirnode: nx_test_dirnode.o libnexus.a
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

.PHONY: clean
clean:
	rm *.o $(tests) libnexus.a
