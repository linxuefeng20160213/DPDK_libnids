#Makefile
#

MAJOR_VER = 1
MINOR_VER = 0.0
VERSION = httpsniff V$(MAJOR_VER).$(MINOR_VER)

CROSS_COMPILE =
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
STRIP = $(CROSS_COMPILE)strip

CFLAGS=-g -Wall -I.
APP=httpsniff
LIBS_CFLAGS	= -I../src
MYLIBDIR=/usr/local/lib
DPDKLIBDIR=/home/vvarghes/Projects/dpdk-2.2.0/x86_64-native-linuxapp-gcc/lib
LIBNIDS=/home/vvarghes/Projects/dpdk-2.2.0/examples/libnids/libnids-1.24/src/build
LIBS=-l$(LIBNIDS)/libnids.a -l$(DPDKLIBDIR)/libdpdk.a -lgthread-2.0 -lnsl -lcrypto
OBJS=httpsniff.o

all: ver $(APP)
.c.o:
	$(CC) $(CFLAGS) $(INCDIR) -c -I. $(LIBS_CFLAGS) $<
$(APP): $(OBJS)	
	$(CC) $(CFLAGS) -o $(APP) $(OBJS) $(LIBS)

clean:
	rm -f *.o
	rm -f $(APP)

ver:
	./ver.sh
	@echo "#define VERSION \"$(VERSION)\"">>ver.h
	@echo "">>ver.h
	@echo "#endif">>ver.h
