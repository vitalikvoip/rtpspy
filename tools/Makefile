CC=gcc
CFLAGS=-I. -ggdb -Wall
LIBS=
DEPS=
OBJ=dump.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

dumper: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o dumper $(LIBS)

.PHONY: clean
clean:
	rm dumper $(OBJ)
