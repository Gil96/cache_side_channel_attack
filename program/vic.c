#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include "aes.h"
#include <string.h>

#define LOGICAL_CORE 7            // logical core where this process will run on
#define W 8                       //  associativity number of L1
#define STRIDE (SIZE32KB/W)       //  step distance between the consecutive accesses in order to fill a particular line of L1


void cpu_setup();

unsigned char * convert_plaintext(char * input);


int main(int argc, char *argv[]) {

    cpu_setup();


    // TO-DO: Replace everything above for real OpenSSL call.

    
// plaintext configuration
    const unsigned char *p = convert_plaintext(argv[1]); 

// output configuration
    unsigned char * out = malloc(sizeof(char) * 16);

// 10-round AES 128-bit-key configuration
    AES_KEY * key = malloc(sizeof(AES_KEY));
    key->rounds =  10;                          
    
// Place the secret key here
	unsigned char k[16] =  // no need for [16]
    {255,255,255,255
	,255,255,255,255
	,255,255,255,255
	,255,255,255,255};


// creates the round key from the secret key
    if (AES_set_encrypt_key( k, 128, key) != 0)
        printf("AES_set_encrypt_key ERROR");
    

// print aes table L1 lines
    AES_print(p,out, key);


// AES-128bit ECB encryption
    for(register int rep = 0; rep < REPETITIONS; rep++){
        AES_encrypt(p, out, key);
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

