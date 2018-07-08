DTRACE = dtrace # the dtrace executable

build = \
        @if [ -z "$V" ]; then \
                echo '    [$1]  $@'; \
                $2; \
        else \
                echo '$2'; \
                $2; \
        fi

probes_SOURCES := backend_sgx.probes.d

probes_OBJECTS := $(patsubst %.d,%.o,$(probes_SOURCES))
probes_HEADERS := $(patsubst %.d,%.h,$(probes_SOURCES))

probes_library := libnexus_probes.a


all: $(probes_library)

%.h: %.d
	$(call build,DTRACE,$(DTRACE) -C -h -s $< -o $@)

%.o: %.d
	$(call build,DTRACE,$(DTRACE) -C -G -s $< -o $@)

$(probes_library): $(probes_HEADERS) $(probes_OBJECTS)
	$(call build,AR,$(AR) rcs $@ $(probes_OBJECTS))
	@cp $@ ../build

headers: $(probes_HEADERS)

.PHONY: clean
clean:
	rm -f $(probes_HEADERS) *.o *.a
