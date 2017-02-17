include ../build.mk

OBJS := hashmap.o slog.o sds.o seqptrmap.o elasticqueue.o elasticarray.o xdr.o xdr_mem.o\
	linenoise.o
CC := gcc

ifeq ($(UCAFS_DEV), 1)
	FLAGS := -O0 -g
else
	FLAGS := -O2
endif

all: libthird.a

libthird.a: $(OBJS)
	ar cr $@ $^

%.o: %.c
	$(CC) -g -c $^ -o $@

.PHONY: clean
clean:
	rm -rf *.o *.a
