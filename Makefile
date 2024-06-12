LDLIBS += -lpcap -g

all: tcp-block

tcp-block: tcp-block.c tcp-block.h headers.h

clean:
	rm -f tcp-block *.o

