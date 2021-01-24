import sys
import time
import os
import statistics as st


FILE_NAME = "atk.c"
PAUSE_TIME = 5
REPETITIONS = 10
SECRET = [20,20,20,20,20,20,20,20,20,20,20,20,20,20,20,20]
T0_LINE = 13
OFFSET = 0

W = {"name": "WAIT_TIME ", "start": 0, "end": 50, "step": 50}

I = {"name": "I ", "start": 32, "end": 256, "step": 2}
N = {"name": "N ", "start": 128, "end": 180, "step": 20}

It = {"name": "It ", "start": 2, "end": 20000, "step": 2}
Nt = {"name": "Nt ", "start": 128, "end": 50, "step": 10}



def main():

    if (str(sys.argv[1]) is '1'):
        test1()
    elif (str(sys.argv[1]) is '2'):
        test2()
    else:
        print("No test was performed!")




def test1():

    I_name = I["name"]
    N_name = N['name']

    i = N["start"]

    # Modify atk.c with the current N value
    change(FILE_NAME, N_name , i )
    # Register results with N = i
    write_results(1, "N = " + str(i))
    
    ii = I["start"]
    while (ii < I["end"]):
            
        # Modify atk.c with the current I value    
        change(FILE_NAME , I_name, ii )

        n_half_bytes = []
        rep = 0
        for rep in range(REPETITIONS):

            # Pause to cool CPU
            time.sleep(PAUSE_TIME)
            # Clean, compile, run attack
            os.system("make clean; make; ./atk")
            # Pause to cool CPU
            time.sleep(PAUSE_TIME)
            # run crypto-analysis program
            os.system("python3 crypto.py")

            # get the number of half key bytes discovered by the attack
            dk = read_disc_key_file()
            n_half_bytes.append(get_n_discovered_bits(dk, SECRET))


        # write averaged half key number discovered in results file
        content = str(ii) + "\t" + str(st.mean(n_half_bytes))
        write_results(1, content )

        # Increment cicle variable
        ii *= I["step"]





def test2():
    
    It_name = It["name"]
    Nt_name = Nt['name']

    i = Nt["start"]

    # Modify atk.c with the current N value
    change(FILE_NAME, Nt_name , i )
    # Register results with N = i
    write_results(2, "N = " + str(i))
    
    ii = It["start"]
    while (ii < It["end"]):
            
        # Modify atk.c with the current I value    
        change(FILE_NAME , It_name, ii )

        # 1 on correct tbox answer; 0 when not
        capacity = []
        rep = 0
        while(rep < REPETITIONS):
            rep += 1

            # Pause to cool CPU
            time.sleep(PAUSE_TIME)
            # Clean, compile, run attack
            os.system("make clean; make; ./atk")
            # Pause to cool CPU
            time.sleep(PAUSE_TIME)
            # run crypto-analysis program
            os.system("python3 crypto.py")
            # get the number of half key bytes discovered by the attack
            offset, t0 = read_disc_tbox_file()

            if ((t0 == T0_LINE) and (offset == OFFSET)):
                capacity.append(1)
            else:
                capacity.append(0)

        # write averaged half key number discovered in results file
        content = str(ii) + "\t" + str(st.mean(capacity))
        write_results(2, content )

        # Increment cicle variable
        ii *= It["step"]






# Auxiliar Functions

def write_results(test_number, line):

    result_file = "result" + str(test_number) + ".out"

    with open(result_file, 'a') as file:
        file.write( line + "\n")



def performance1():

    l=0
    unused_lines = [6, 31, 52, 58, 59]

    while(True):
        try:
            timings  = read_files(l, "meas")
            l+=1
        except IOError:
            break

        avg = st.mean(timings)
        dev = st.stdev(timings)

        line_score = []
        meas_score = []

        for line in unused_lines:
            if (timings[line] < (avg + 1*dev)):
                line_score.append(timings[line]/avg)
        meas_score.append(st.mean(line_score))
    
    attack_score = st.mean(meas_score)

    attack_score = float("{0:.4f}".format(attack_score))

    return attack_score




def get_n_discovered_bits(key1, key2):


    n_common_half_keys = 0

    if(len(key1) is not len(key2)):
        print("Key1 has not the same size as key2")

    for i in range(len(key1)):

        if((key1[i] % 16) == (key2[i] % 16)):
            n_common_half_keys += 1
        if((key1[i] >> 4) == (key2[i] >> 4)):
            n_common_half_keys += 1

    return n_common_half_keys






def change(file_name, variable_name, amount ):

    # Read file
    with open(file_name, 'r') as file:
        data = file.readlines()

    # Perform modifications
    for l, line in enumerate(data):
        if variable_name in line:
            data[l] = "#define " + str(variable_name) + str(amount) + "\n"
            break

    # Write in File Modification
    with open(file_name, 'w') as file:
        file.writelines( data )


def read_files(l, file_name):
    
    meas_file = open("side_channel_info/" + file_name + "#" + str(l) + ".out", "r")
    plaintext_raw = meas_file.readline()
    scores = [int(i) for i in meas_file]
    meas_file.close()
    
    return scores


def read_disc_key_file():
    
    table_file = open("discovered_key_.out", "r")
    discovered_key = [int(i) for i in table_file]
    table_file.close()
    
    return discovered_key


def read_disc_tbox_file():

    tbox_file = open("tbox_discovered_.out", "r")
    values = [int(i) for i in tbox_file]
    tbox_file.close()
    
    return values[0], values[1]



main()