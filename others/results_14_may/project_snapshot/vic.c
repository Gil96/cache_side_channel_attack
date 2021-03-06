/* 
vic.c
    
    DESCRIPION
        Victim program that fills a random L1 line in a endless loop
        Victim and attacker run in the same CPU
        This is a try to implement aes_core code from openssl (ECB)
            ->  Only 1ºRound implemented

    Notes:
        Assumes the it receives the proper sized plaintext - 16B

    CPU details:
        model name.............. Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
        CPU(s).................. 8
        On-line CPU(s) list..... 0-7
        Thread(s) per core...... 2
        Core(s) per socket...... 4
        L1d_cache_size.......... 32768 B
        L1d_assoc............... 8
        L1d_line_size........... 64 B    
*/



#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include "aes.h"
#include <string.h>

#define LOGICAL_CORE 7              // logical core where this process will run on
#define W 8                       //  associativity number of L1
#define STRIDE (SIZE32KB/W)       //  step distance between the consecutive accesses in order to fill a particular line of L1


void cpu_setup();

unsigned char * convert_plaintext(char * input);


int main(int argc, char *argv[]) {

    cpu_setup();
    
// plaintext configuration
    const unsigned char *p = convert_plaintext(argv[1]); 

// output configuration
    unsigned char * out = malloc(sizeof(char) * 16);

// 10-round AES 128-bit-key configuration
    AES_KEY * key = malloc(sizeof(AES_KEY));
    key->rounds =  10;                          
    
	unsigned char k[16] = 
    {255,255,255,255
	,255,255,255,255
	,255,255,255,255
	,255,255,255,255}; // place key here !!

    if (AES_set_encrypt_key( k, 128, key) != 0)
        printf("AES_set_encrypt_key ERROR");
    

    AES_encrypt(p, out, key);

    return 0;
}

unsigned char * convert_plaintext(char * input){

    char temp[4];
    unsigned char * in = malloc(sizeof(char)*16);

    // printf("input: %s\n", input);

    for (int i = 0, l = 0, e = 0; i< strlen(input); i++){

        if (input[i] == '.') {
            temp[e] = '\0';
            in[l] = (unsigned char) atoi(temp);
            e=0;
            l++;

        }else{
            temp[e] = input[i];
            e++;
        }
    }

    return in;


}






void cpu_setup(){

    cpu_set_t mask;    
    CPU_ZERO( &mask );
    CPU_SET( LOGICAL_CORE, &mask );
    if( sched_setaffinity( getpid(), sizeof(mask), &mask ) == -1 ){
        printf("WARNING: Could not set CPU Affinity...\n");
    }
}

