CC=gcc
CFLAGS=-Wall
LDLIBS=-lcrypto

all: alice bob eve

alice: alice.c
	$(CC) $(CFLAGS) -o alice alice.c $(LDLIBS)

bob: bob.c
	$(CC) $(CFLAGS) -o bob bob.c $(LDLIBS)

eve: eve.c
	$(CC) $(CFLAGS) -o eve eve.c $(LDLIBS)

clean:
	rm -f alice bob eve
