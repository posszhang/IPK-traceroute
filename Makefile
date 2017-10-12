TRACE_S = traceroute.cpp

CC=g++
CFLAGS=-std=c++11

all: traceroute

traceroute: traceroute.h traceroute.cpp
	$(CC) $(CFLAGS) $(TRACE_S) -o trace

clean:
	rm trace