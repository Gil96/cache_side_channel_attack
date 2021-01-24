#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include "aes.h"

#define REPETITIONS 300000        // number of encryption repetitions
#define LOGICAL_CORE 7            // logical core where this process will run on
#define W 8                       //  associativity number of L1
#define STRIDE (SIZE32KB/W)       //  step distance between the consecutive accesses in order to fill a particular line of L1

void cpu_setup();

unsigned char * convert_plaintext(char * input);

int main(int argc, char *argv[]) {
    
    // Makes thread to run on a certain logic core
    cpu_setup();

    // Secret key
    unsigned char secret_key[] = 
        {20,20,20,20,
        20,20,20,20,
        20,20,20,20,
        20,20,20,20};

    // plaintext configuration
    const unsigned char *p = convert_plaintext(argv[1]);

    // output configuration
    unsigned char out[16]; 

    // 10-round AES 128-bit-key configuration
    AES_KEY * kptr, key;
    kptr = &key;
    kptr->rounds = 10;

    // creates the round key from the secret key
    if (AES_set_encrypt_key( secret_key, 128, kptr) != 0)
        printf("AES_set_encrypt_key ERROR");
    
    // AES-128bit ECB encryption
    for(register int rep = 0; rep < REPETITIONS; rep++){
        AES_encrypt(p, out, kptr);
    }
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

