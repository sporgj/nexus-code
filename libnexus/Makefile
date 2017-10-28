

INCLUDES := -I../libnexus
CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 $(INCLUDES)



objs := nx_dirops.o

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: libnexus.a

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)

libnexus.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)

.PHONY: clean
clean:
	rm -f $(wildcard *.o *.a)
