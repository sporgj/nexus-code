include ../../../../../build.mk

ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g
else
	CFLAGS += -O2
endif


ifeq ($(SGX_MODE), SIM)
	sgx_trts_lib    := sgx_trts_sim
	sgx_svc_lib     := sgx_tservice_sim
else ifeq ($(SGX_MODE), HW)
	sgx_trts_lib    := sgx_trts
	sgx_svc_lib     := sgx_tservice
else
        $(error Invalid SGX MODE)
endif


INCLUDE := -I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/stlport \
	-I$(LIBGCC_PATH) \
	-Imbedtls/include \
	-Ilibnexus_trusted \
	-I. \
	-I..

CFLAGS  += -nostdinc -pedantic \
	-fvisibility=hidden -fpie -fPIC -fstack-protector -mpclmul -maes -mavx -w \
	-W -Wall -Werror -D_GNU_SOURCE -Wno-nonnull -Wno-unused-parameter -std=gnu11 -fPIC\
	-Werror=implicit-function-declaration -Wconversion

liblua_a_SOURCES := \
	lauxlib.c \
	lbaselib.c \
	lbitlib.c \
	lcorolib.c \
	ldblib.c \
	liolib.c \
	lmathlib.c \
	loadlib.c \
	loslib.c \
	lstrlib.c \
	ltablib.c \
	lualib.h \
	lutf8lib.c \
	linit.c \
	\
	lapi.c lapi.h \
	lcode.c lcode.h \
	lctype.c lctype.h \
	ldebug.c ldebug.h \
	ldo.c ldo.h \
	ldump.c \
	lfunc.c lfunc.h \
	lgc.c lgc.h \
	llex.c llex.h \
	llimits.h \
	lmem.c lmem.h \
	lobject.c lobject.h \
	lopcodes.c lopcodes.h \
	lparser.c lparser.h \
	lprefix.h \
	lstate.c lstate.h \
	lstring.c lstring.h \
	ltable.c ltable.h \
	ltm.c ltm.h \
	lundump.c lundump.h \
	lvm.c lvm.h \
	lzio.c lzio.h \
	\
	luaxlib.h \
	luaconf.h \
	lua.h lua.hpp \
	\
	compat-layer.c compat-layer.h

source_files := $(filter %.c %.s,$(liblua_a_SOURCES))
object_files := $(source_files:.c=.o)

output_library := liblua.a

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi



$(output_library): $(object_files)
	@echo $(object_files)
	$(call build,AR,$(AR) rcs $@ $^)

%.o: %.c
	$(call build,CC,$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@)


.PHONY: clean
clean:
	rm -rf *.o *.a
