CFLAGS=-Wall -g

DEST=/usr/local
LIBDEST=$(DEST)/lib
INCDEST=$(DEST)/include

SRCS=smbdes.c smbencrypt.c smbmd4.c smbutil.c
OBJS=smbdes.o smbencrypt.o smbmd4.o smbutil.o

libntlm.a: $(OBJS)
	ar cru libntlm.a $(OBJS)
	ranlib libntlm.a

install: libntlm.a ntlm.h
	install libntlm.a $(LIBDEST)
	install ntlm.h $(INCDEST)

clean: 
	rm -f *.a *.o *~ *.bak \#*\#

depend:
	makedepend $(SRCS)
# DO NOT DELETE

smbdes.o: smbdes.h
smbencrypt.o: /usr/include/unistd.h /usr/include/sys/feature_tests.h
smbencrypt.o: /usr/include/sys/types.h /usr/include/sys/isa_defs.h
smbencrypt.o: /usr/include/sys/machtypes.h /usr/include/sys/int_types.h
smbencrypt.o: /usr/include/sys/select.h /usr/include/sys/time.h
smbencrypt.o: /usr/include/sys/time.h /usr/include/sys/unistd.h
smbencrypt.o: /usr/include/stdlib.h /usr/include/string.h
smbencrypt.o: /usr/include/ctype.h smbbyteorder.h smbdes.h smbmd4.h
smbmd4.o: smbmd4.h
smbutil.o: /usr/include/unistd.h /usr/include/sys/feature_tests.h
smbutil.o: /usr/include/sys/types.h /usr/include/sys/isa_defs.h
smbutil.o: /usr/include/sys/machtypes.h /usr/include/sys/int_types.h
smbutil.o: /usr/include/sys/select.h /usr/include/sys/time.h
smbutil.o: /usr/include/sys/time.h /usr/include/sys/unistd.h
smbutil.o: /usr/include/stdlib.h /usr/include/stdio.h
smbutil.o: /usr/include/sys/va_list.h /usr/include/ctype.h
smbutil.o: /usr/include/assert.h /usr/include/string.h ntlm.h smbencrypt.h
smbutil.o: smbbyteorder.h
