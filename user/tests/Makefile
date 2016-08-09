include ../header.mk
EXTRA_FLAGS = -I../ $(patsubst -I%, -I../%, $(INCFLAGS))
TEST_LIBS = $(patsubst -L%, -L../%, $(LIBS))
TEST_OBJS = $(patsubst %.o, ../%.o, $(OBJS))

PROGS = test_filebox\
	test_crypto

tests: $(PROGS)

# for now
build:
	cd ../ && make && cd tests

ucafs.a: build $(TEST_OBJS)
	ar cr $@ $(wordlist 2, $(words $^), $^)

define make-test-target
$(1): $(1).cc ucafs.a
	$(CXX) $$(CPPFLAGS) $$(EXTRA_FLAGS) $(1).cc ucafs.a $$(TEST_LIBS) -o $(1)
endef

$(foreach element,$(PROGS),$(eval $(call make-test-target,$(element))))

clean:
	rm -rf *.fbox ucafs.a $(PROGS)
