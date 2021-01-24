TARGETS = atk atk_enc vic_enc
PAPILIB=/home/verao9/papi-6.0.0/src/libpapi.a
PAPIH=/home/verao9/papi-6.0.0/src
CFLAGS = -Wall
AES_PATH = /home/verao9/Desktop/cache_side_channel_attack/usr/local/ssl/lib

all: $(TARGETS)
	rm -f side_channel_info/*.*

atk: atk.c
	$(CC) $(CFLAGS) -I $(PAPIH) atk.c $(PAPILIB) -o atk

# On the terminal:
# $ export LD_LIBRARY_PATH=/home/..../ssl/lib:LD_LIBRARY_PATH

vic_enc: vic_enc.c
	$(CC) -L$(AES_PATH) $(CFLAGS) -o vic_enc vic_enc.c -lcrypto

atk_enc: atk_enc.c
	$(CC) -L$(AES_PATH) $(CFLAGS) -o atk_enc atk_enc.c -lcrypto

clean:
	rm -f $(TARGETS) *.o *.stderr *.stdout core *~
	rm -f *_.out
	rm -f side_channel_info/*.*

