CC=gcc
#CFLAGS=-I. -ggdb -Wall -DWITH_DEBUG
CFLAGS=-I. -ggdb -Wall
LIBS=-lpcap
DEPS=globals.h rtp.h config.h stream_table.h hashmap.h
OBJ=rtpspy.o config.o stream_table.o hashmap.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

rtpspy: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o rtpspy $(LIBS)

.PHONY: clean
clean:
	rm rtpspy $(OBJ)
