CC = gcc
INCLUDES = -I/usr/local/gcc/include/ $(pkg-config --cflags libsodium)
DEFINES = 
CFLAGS = -std=c11 -g -Wall
LDFLAGS = $(pkg-config --libs libsodium)
LIBS = -lsodium

SRCS = main.c
OBJS = $(SRCS:.c=.o)
HS= $(wildcard *.h)

.PHONY: clean

all:  chch

chch:  $(OBJS) $(HPPS)
		$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $(OBJS) $(LDFLAGS) $(LIBS) $(STATIC_LIBS)

.c.o:
		$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -c $< -o $@

clean: 
		$(RM) chch *.o *~
