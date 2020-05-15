TARGETS = atk vic
PAPILIB=/home/verao9/papi-6.0.0/src/libpapi.a
PAPIH=/home/verao9/papi-6.0.0/src

all: $(TARGETS)
	rm -f results/*.*	

atk: atk.c
	$(CC) $(CFLAGS) -I $(PAPIH) atk.c $(PAPILIB) -o atk

vic.o: vic.c
	$(CC) -c vic.c

aes.o: aes.c
	$(CC) -c aes.c	

vic: vic.o aes.o
	$(CC) -o vic vic.o aes.o
	rm *.o

clean:
	rm -f $(TARGETS) *.o *.stderr *.stdout core *~
	rm -f results/*.*
