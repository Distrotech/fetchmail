DESTDIR = /usr/local/bin
CFLAGS = $G $O $S
O = -m486 -O2
S = -s
G =

mime64:	mime64.c
	$(CC) $(CFLAGS) -o $@ $^

install:mime64
	install -s mime64 $(DESTDIR)

clobber:
	rm -f mime64
