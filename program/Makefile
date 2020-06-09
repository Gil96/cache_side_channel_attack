TARGETS = atk vic
PAPILIB=/home/verao9/papi-6.0.0/src/libpapi.a
PAPIH=/home/verao9/papi-6.0.0/src
PATH_AES =/openssl-0.9.8/crypto/aes/aes_core.c


all: $(TARGETS)
	rm -f lines_used_debug/*.*
	rm -f side_channel_info/*.*

atk: atk.c
	$(CC) $(CFLAGS) -I $(PAPIH) atk.c $(PAPILIB) -o atk


# This code impacts the table addresses & Offset \

vic.o: vic.c
	$(CC) -c vic.c

aes_core.o: aes_core.c
	$(CC) -c aes_core.c	

vic: vic.o aes_core.o
	$(CC) -o vic vic.o aes_core.o
	rm *.o

clean:
	rm -f $(TARGETS) *.o *.stderr *.stdout core *~
	rm -f lines_used_debug/*.*
	rm -f side_channel_info/*.*
