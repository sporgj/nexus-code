include ../build.mk

CFLAGS += -I../ $(App_C_Flags)

LIBS := -lmbedcrypto $(App_Link_Flags) -luuid

tests := test_dirnode test_dirops test_misc

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

test_dirnode: nx_test_dirnode.o unity/unity.o libnexus.a
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

test_dirops: nx_test_dirops.o unity/unity.o libnexus.a
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

test_misc: nx_test_misc.o unity/unity.o libnexus.a
	$(call build,CC,$(CC) $^ $(LIBS) -o $@)

.PHONY: clean
clean:
	rm *.o $(tests) libnexus.a
