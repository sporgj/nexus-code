OBJS := hashmap.o slog.o sds.o seqptrmap.o elasticqueue.o elasticarray.o xdr.o xdr_mem.o
CC := gcc

all: libthird.a

libthird.a: $(OBJS)
	ar cr $@ $^

%.o: %.c
	$(CC) -g -c $^ -o $@

.PHONY: clean
clean:
	rm -rf *.o
