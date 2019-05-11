include ../build.mk

buildpath = ../build

libs := -Wl,--whole-archive ../libnexus.a -Wl,--no-whole-archive -luuid -lpthread -lcurl -lreadline

LDFLAGS := -L$(SGX_SDK)/lib64


ifeq ($(SGX_MODE), SIM)
	libs += -lsgx_urts_sim -lsgx_uae_service_sim
else ifeq ($(SGX_MODE), HW)
	libs += -lsgx_urts -lsgx_uae_service
else
        $(error Invalid SGX MODE)
endif


INCLUDES := -I../libnexus -I../
CFLAGS = -g -W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter  -std=gnu11 $(INCLUDES)
LDFLAGS +=  -Wl,--whole-archive

CC = gcc
AR = ar


exec_objs :=	main.o \
		filler.o \
		create_volume.o \
		delete_volume.o \
		repl_volume.o \
		fs.o


execs := nexus_shell


build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi


all: $(execs)

% : %.c
	$(call build,CC,$(CC) $(CFLAGS) $< -o $@)

%.o : %.c
	$(call build,CC,$(CC) $(CFLAGS) -c $<  -o $@)

%.a : %.o
	$(call build,AR,$(AR) rcs $@ $^)

nexus_shell: $(exec_objs) ../libnexus.a
	$(call build,CC,$(CC) $(CFLAGS)  $(exec_objs) $(LDFLAGS) $(libs) -o $@)


define cscope-all-sources
	( find . $(RCS_FIND_IGNORE) \
		\( -name '*.[chS]' -o -name '*.cc' \) -print; \
	)
endef


cscope:
	$(call build,FILELIST,(echo \-k; echo \-q; $(cscope-all-sources)) > cscope.files)
	$(call build,MAKE,cscope -b)




clean:
	rm -f  cscope.* $(execs) *.o *.a


.PHONY: clean
