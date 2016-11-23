PROGS := gen_file
CFLAGS := -std=c11 -O3

gen_file: gen_file.c
	gcc $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rf $(PROGS)
