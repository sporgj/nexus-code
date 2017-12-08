
buildpath = ../build

INCLUDES = -I. -I../mbedtls-2.6.0/include

CFLAGS = -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC


ifeq ($(DEBUG), 1)
	CFLAGS += -g3 -DDEBUG
endif


objs :=	nexus_main.o \
	nexus_volume.o \
	nexus_util.o \
	nexus_key.o \
	nexus_uuid.o \
	nexus_raw_file.o \
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
	@cp $^ $(buildpath)

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@)


libnexus.a: $(objs)
	$(call build,AR,$(AR) rcs $@ $^)

define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)



clean:
	rm -f $(wildcard *.o *.so *.a) cscope.*a


.PHONY: clean
