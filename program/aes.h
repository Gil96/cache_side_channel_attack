/*

DESCRIPTION:
    This file contains all the data structures as well as tables
    required by aes.c.

*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#define AES_MAXNR 14
#define REPETITIONS 1000000          // works with aes-1m & atk-10k 
#define SIZE32KB (32*1024)        //  represents 32 KB


typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;


# define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

typedef struct aes_key_st {
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
} AES_KEY;


void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

void AES_print(const unsigned char *in, unsigned char *out, const AES_KEY *key);

void L1_line_printer( char * name, void * addr);

void L1_line_printer_const( char * name, const void * addr);

int L1_line_translator( void * addr);

int L1_line_translator_const( const void * addr);

int cmp (const void * a, const void * b);

int L1_cache_block_offset_translator( const void * addr);