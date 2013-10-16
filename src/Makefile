# Wesam Lootah.
# Choose the compiler
#CC = CC
CC = gcc
INSTALL = install
  
# Compiler options
#CCOPTS = -O3 -mv8
#CCOPTS = -g -Wall

LIBS = -lpcap -lnet -lssl -lcrypto -lnetlink

OPENSSL = -lssl
  
# Header files
HEADERS=tarp_error.h wl_time.h

OBJECTS= tarp_error.o tarp_capture.o tarp_net.o tarp_neigh.o tarp_kernel.o tarp_signal.o tarp_crypto.o tarp_ticket.o tarp_hosts.o
  
# tarpd
tarpd: tarpd.o $(OBJECTS)
	$(CC) $(CCOPTS) tarpd.o $(OBJECTS) -o tarpd $(LIBS)

tarpd.o: tarpd.c
	$(CC) -I ../include -c tarpd.c $(TEST)

debug: tarpd_d.o $(OBJECTS)
	$(CC) $(CCOPTS) tarpd_d.o $(OBJECTS) -o tarpd $(LIBS)

tarpd_d.o: tarpd.c
	$(CC) -I ../include -c tarpd.c -o tarpd_d.o -D DEBUG $(TEST)

debug2: tarpd_d2.o $(OBJECTS)
	$(CC) $(CCOPTS) tarpd_d2.o $(OBJECTS) -o tarpd $(LIBS)

tarpd_d2.o: tarpd.c
	$(CC) -I ../include -c tarpd.c -o tarpd_d2.o -D DEBUG -D DEBUG_LEVEL2

debug3: tarpd_d3.o $(OBJECTS)
	$(CC) $(CCOPTS) tarpd_d3.o $(OBJECTS) -o tarpd $(LIBS)

tarpd_d3.o: tarpd.c
	$(CC) -I ../include -c tarpd.c -o tarpd_d3.o -D DEBUG -D DEBUG_LEVEL2 -D DEBUG_LEVEL3

tarp_net.o: tarp_net.c
	$(CC) -I ../include -c tarp_net.c

tarp_kernel.o: tarp_kernel.c
	$(CC) -I ../include -c tarp_kernel.c

tarp_signal.o: tarp_signal.c
	$(CC) -I ../include -c tarp_signal.c

tarp_crypto.o: tarp_crypto.c
	$(CC) -I ../include -c tarp_crypto.c

tarp_hosts.o: tarp_hosts.c
	$(CC) -I ../include -c tarp_hosts.c

tarp_error.o: tarp_error.c
	$(CC) -I ../include -c tarp_error.c

%.o : %.c $(HEADERS) Makefile
	$(CC) -I ../include -c $<
  

tarp_dlta.o: tarp_dlta.c
	$(CC) -I ../include -c tarp_dlta.c

tarp_dlta: tarp_dlta.o $(OBJECTS)
	$(CC) $(CCOPTS) tarp_dlta.o $(OBJECTS) -o tarp_dlta $(LIBS)

install:
	$(INSTALL) -m 744 tarpd /usr/bin
	$(INSTALL) -d /etc/tarp
	$(INSTALL) -m 644 ../config/tarp_config /etc/tarp
	$(INSTALL) -m 644 ../config/ex_pub_key /etc/tarp
	$(INSTALL) -m 644 ../config/ex_ticket /etc/tarp
	$(INSTALL) -m 644 ../config/known_hosts /etc/tarp

uninstall:
	rm /usr/bin/tarpd
	rm /etc/tarp/tarp_config
	rm /etc/tarp/ex_pub_key
	rm /etc/tarp/ex_ticket
	rm /etc/tarp/known_hosts
	rmdir /etc/tarp	
clean:
	rm *.o *~ tarpd tarp_dlta
