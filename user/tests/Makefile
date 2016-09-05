include ../header.mk

all: reset
	make -C ../ tests

reset:
	rm -rf repo/* && rm -rf repo/.afsx/*

clean:
	rm -rf *.dnode libucafs.a $(TESTS)
