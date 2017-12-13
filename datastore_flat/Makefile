include ../build.mk


INCLUDES := -I../libnexus

CFLAGS   := -W -Wall -Werror \
	    -Wno-nonnull -Wno-unused-parameter -Wno-attributes \
	    -D_GNU_SOURCE \

# setup debug info
ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g3
else
	CFLAGS += -O2
endif



LDFLAGS  := 

libs     := 



objs := main.o \



build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: datastore_flat.a
	@cp datastore_flat.a ../build

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@)


datastore_flat.a:  $(objs) 
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
	rm -f $(wildcard *.o *.a *.so) cscope.*


.PHONY: clean cscope
