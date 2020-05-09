from pyfinite import ffield  # To perform GF(256) multiplications
from math import log2        # To calculate delta bits



#1Round vars
k = [[x for x in range(256)] for y in range(16)]

#2Round vars
F = ffield.FField(8)
lk = [[x for x in range(65536)] for y in range(4)]
hx = [x for x in range(4)]
line_hx = [x for x in range(4)]
lk_results = [x for x in range(4)]

#assumes no offset ie each key byte only and only has the same specific first delta bits  
part_key = [y for y in range(16)]
delta = 16
delta_bits = log2(delta)

#sbox - 256 
s = [
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


def round_1_attack():

    l=0
    while(True):
        
        try:
            meas_file = open("results/meas#" + str(l) + ".out", "r")
            vic_file = open("results/victim#" + str(l) + ".out", "r")
            l+=1
        except IOError:
            break

        first = vic_file.readline()
        first = first[:-2]

        plaintext = [int(i) for i in first.split('.')]
        tables = [int(i) for i in vic_file]

        results = [int(i) for i in meas_file]

        meas_file.close()
        vic_file.close()

        u_lines = []
        for index, item in enumerate(results):
            if item < 500:
                u_lines.append(index) 


        for ti, table in enumerate (tables):
            for j in range(0,4):
                for hki in range(0,256):
                    hacc = plaintext[ti + j*4] ^ hki
                    line_hacc = (table + (hacc//delta)) % 64
                    if line_hacc in u_lines:
                        k[ti + j*4][hki] = -1
        

def round_2_attack():


    l=0
    while(True):

        try:
            meas_file = open("results/meas#" + str(l) + ".out", "r")
            vic_file = open("results/victim#" + str(l) + ".out", "r")
            l+=1

        except IOError:
            break

        first = vic_file.readline()
        first = first[:-2]

        p = [int(i) for i in first.split('.')]
        tables = [int(i) for i in vic_file]

        results = [int(i) for i in meas_file]

        meas_file.close()
        vic_file.close()

        u_lines = []
        for index, item in enumerate(results):
            if item < 500:
                u_lines.append(index)


        for low_hkA in range(0, 16):
            for low_hkB in range(0, 16):
                for low_hkC in range(0, 16):
                    for low_hkD in range(0, 16):
                        hk0 = part_key[0] + low_hkA
                        hk1 = part_key[1] + low_hkB
                        hk2 = part_key[2] + low_hkC
                        hk3 = part_key[3] + low_hkD
                        hk4 = part_key[4] + low_hkA
                        hk5 = part_key[5] + low_hkB
                        hk6 = part_key[6] + low_hkC
                        hk7 = part_key[7] + low_hkD
                        hk8 = part_key[8] + low_hkA
                        hk9 = part_key[9] + low_hkB
                        hk10 = part_key[10] + low_hkC
                        hk11 = part_key[11] + low_hkD
                        hk12 = part_key[12] + low_hkA
                        hk13 = part_key[13] + low_hkB
                        hk14 = part_key[14] + low_hkC
                        hk15 = part_key[15] + low_hkD

                        #X2
                        hx[0] = s[p[0] ^ hk0] ^ s[p[5] ^ hk5] ^ F.Multiply(2, s[p[10]^hk10]) ^ F.Multiply(3, s[p[15]^hk15]) ^ s[hk15] ^ part_key[2]
                        #X5
                        hx[1] = s[p[4] ^ hk4] ^ F.Multiply(2,s[p[9] ^ hk9]) ^ F.Multiply(3, s[p[14]^hk14]) ^ s[p[3]^hk3] ^ s[hk14] ^ part_key[1] ^ part_key[5]
                        #X8
                        hx[2] = F.Multiply(2,s[p[8] ^ hk8]) ^ F.Multiply(3,s[p[13] ^ hk13]) ^ s[p[2]^hk2] ^ s[p[7]^hk7] ^ s[hk13] ^ part_key[0] ^ part_key[4] ^ part_key[8] ^ 1
                        #X15
                        hx[3] = F.Multiply(3,s[p[12] ^ hk12]) ^ s[p[1]^hk1] ^ s[p[6]^hk6] ^ F.Multiply(2, s[p[11]^hk11]) ^ s[hk12] ^ part_key[3] ^ part_key[7] ^ part_key[11] ^ part_key[15]
                        

                        for i in range(0,4):
                            line = (tables[(2-i)%4] + (hx[i]//delta)) % 64
                            line_hx[i] = line
                            if (line in u_lines):
                                lk[i][(low_hkA<<12) + (low_hkB<<8) + (low_hkC<<4) + low_hkD] = -1

                        #implement?: soon he detects there is only 1 combination per lk[i], breaks


                        #if number of measurement samples are not enough consider using others equations ...
                        # ...see Desktop/Others/AES_1-Round_Equations.txt
                        


    for index in range(0,4):
        for ij in range(0,65536):
            if(lk[index][ij] != -1):
                print(lk[index][ij])
        print("###")
    

    
    for lk_index, lk_item in enumerate (lk):
        for combination in lk_item:
            if combination != -1:
                lk_results[lk_index] = combination
                break


    hk0 = part_key[0] + ((lk_results[0]>>12) & 0xf)
    hk1 = part_key[1] + ((lk_results[3]>>8) & 0xf)
    hk2 = part_key[2] + ((lk_results[2]>>4) & 0xf)
    hk3 = part_key[3] + ((lk_results[1]) & 0xf)
    hk4 = part_key[4] + ((lk_results[1]>>12) & 0xf)
    hk5 = part_key[5] + ((lk_results[0]>>8) & 0xf)
    hk6 = part_key[6] + ((lk_results[3]>>4) & 0xf)
    hk7 = part_key[7] + ((lk_results[2]) & 0xf)
    hk8 = part_key[8] + ((lk_results[2]>>12) & 0xf)
    hk9 = part_key[9] + ((lk_results[1]>>8) & 0xf)
    hk10 = part_key[10] + ((lk_results[0]>>4) & 0xf)
    hk11 = part_key[11] + ((lk_results[3]) & 0xf)
    hk12 = part_key[12] + ((lk_results[3]>>12) & 0xf)
    hk13 = part_key[13] + ((lk_results[2]>>8) & 0xf)
    hk14 = part_key[14] + ((lk_results[1]>>4) & 0xf)
    hk15 = part_key[15] + ((lk_results[0]) & 0xf)

    print(str(hk0))
    print(str(hk1))
    print(str(hk2))
    print(str(hk3))
    print(str(hk4))
    print(str(hk5))
    print(str(hk6))
    print(str(hk7))
    print(str(hk8))
    print(str(hk9))
    print(str(hk10))
    print(str(hk11))
    print(str(hk12))
    print(str(hk13))
    print(str(hk14))
    print(str(hk15))




#admits it has the same delta bits
#admits the number of delta bits is 4
#in decimal format, considering the bits: XXXX - 0000
def get_partial_key():

    for i , ki in enumerate (k):
        for elem in ki:
            if elem != -1:
                part_key[i] = elem & 0xf0
                break

    print (part_key)



round_1_attack()
get_partial_key()
round_2_attack()