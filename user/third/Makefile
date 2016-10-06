OBJS := hashmap.o slog.o sds.o seqptrmap.o elasticqueue.o elasticarray.o

all: libthird.a

libthird.a: $(OBJS)
	ar cr $@ $^

%.o: %.c
	$(CC) -c $^ -o $@	
