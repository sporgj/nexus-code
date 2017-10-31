

INCLUDES := -I../libnexus
CFLAGS = -g -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 $(INCLUDES)

CC = gcc
AR = ar


exec_objs :=	main.o \
	 	rpc.o  \
		xdr.o  \
		xdr_mem.o


libs := ../libnexus/libnexus.a

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: nexus-afs

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)





nexus-afs: $(exec_objs)
	$(call build,CC,$(CC) $(CFLAGS) $^ $(libs) -o $@)





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
	rm -f $(wildcard  $(exec_objs) $(execs) *.o *.a)
