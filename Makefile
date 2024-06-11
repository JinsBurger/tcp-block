LDLIBS += -lpcap

all: tcp-block

tcp-block: tcp-block.o

clean:
	rm -f tcp-block *.o

