
buildpath = ../build

INCLUDES =

CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC


LIBS = -luuid


objs :=	nexus_fs_ops.o \
	nexus_encode.o \
	nexus_main.o \
	jsmn.o \
	nexus_json.o



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


libnexus.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)
	@cp $@ ../build

define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



clean:
	rm -f $(wildcard *.o *.so *.a) cscope.*


.PHONY: clean
