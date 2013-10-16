# Choose the compiler
#CC = CC
CC = gcc
  
# Compiler options
#CCOPTS = -O3 -mv8
#CCOPTS = -g -Wall

LIBS = -lpcap -lnet -lssl -lcrypto

  
# Header files
HEADERS=tarp_error.h

OBJECTS = 
  
%.o : %.c $(HEADERS) Makefile
	$(CC) $(CCOPTS) -c $<

all: lta tarp_genkeys tarp_viewticket
  
# lta
lta: tarp_lta.o $(OBJECTS)
	$(CC) $(CCOPTS) tarp_lta.o $(OBJECTS) -o lta $(LIBS)

tarp_genkeys: tarp_genkeys.o $(OBJECTS)
	$(CC) $(CCOPTS) tarp_genkeys.o $(OBJECTS) -o tarp_genkeys $(LIBS)

tarp_viewticket: tarp_viewticket.o $(OBJECTS)
	$(CC) $(CCOPTS) tarp_viewticket.o $(OBJECTS) -o tarp_viewticket $(LIBS)

clean: 
	rm *.o lta tarp_genkeys tarp_viewticket *~
