#################################################################
##
## FILE:	Makefile
## PROJECT:	CNT 4007 Project 1 - Professor Traynor
## DESCRIPTION: Compile Project 1
##
#################################################################

CC=gcc
CFLAGS=-g

OS := $(shell uname -s)

# Extra LDFLAGS if Solaris
ifeq ($(OS), SunOS)
	LDFLAGS=-lsocket -lnsl
    endif

all: client server 

client: client.c
	$(CC) client.c -o client -lcrypto

server: server.c
	$(CC) server.c -o server -lcrypto

clean:
	    rm -f client server *.o


