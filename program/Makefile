TARGETS = atk vic
PAPILIB=/home/verao9/papi-6.0.0/src/libpapi.a
PAPIH=/home/verao9/papi-6.0.0/src
CFLAGS = -Wall
AES_PATH = /home/verao9/Desktop/cache_side_channel_attack/usr/local/ssl/lib


all: $(TARGETS)
	rm -f lines_used_debug/*.*
	rm -f side_channel_info/*.*

atk: atk.c
	$(CC) $(CFLAGS) -I $(PAPIH) atk.c $(PAPILIB) -o atk


# On the terminal:
# $ export LD_LIBRARY_PATH=/home/..../ssl/lib:LD_LIBRARY_PATH
vic: vic.c
	$(CC) -L$(AES_PATH) $(CFLAGS) -o vic vic.c -lcrypto

clean:
	rm -f $(TARGETS) *.o *.stderr *.stdout core *~
	rm -f *.out
	rm -f side_channel_info/*.*