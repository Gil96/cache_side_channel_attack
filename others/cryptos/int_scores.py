#interpreter using score of each key byte to determine whether of not its a very likely key
# This interpreter 1-Round runs spends some time but the outcome is pretty good
# 1Round atk Supports some variances or non-regularity from data of measurements
# 2 Round atk is not quite good since the scores are pretty much the same inside the <ki>

# Example of a problem in 2Round:

#   If you have k1 = 255
#   255 can take scores around 2k
#   and 254 can take scores around 2k + (once or twice it got a score of 6k - due to another var in the same cache line)
#   254 eventually catches a line with low score like (10)
#   in the end measuring all up you have 255 with score avg = 2k
#   but 254 will be  > 255, since it got the luck of getting a line with 6k a bunch of times more than 255key

#Conclusion: this happens to be a problem since we are not able to find the key, no matter the number of samples used
#Solution: use a naive.py likaly interpreter

from pyfinite import ffield  # To perform GF(256) multiplications
from math import log2        # To calculate delta bits



# Sbox (256 Elements) 
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


# Round 1 Attack Varables:

delta = 16
#delta_bits = log2(delta)
hk_score = [[0 for x in range(256)] for y in range(16)]
hk_ref = [[0 for x in range(256)] for y in range(16)]

poss_k = [[0 for x in range(delta)] for y in range(16)]
all_part_k = [[]for y in range(16)]      # change name






def round_1_attack():
    
    l=0
    while(True):
        
        try:
            p,tables,scores  = read_files(l)
            l+=1
        except IOError:
            break
        
        for i in range(len(hk_score)):
            for hki in range(0,256):
                hx = p[i] ^ hki
                line_x = (tables[i%4] + (hx//delta)) % 64
                new_score = scores[line_x]

                score = hk_score[i][hki]
                ref = hk_ref[i][hki]

                hk_score[i][hki] =  int (score * (ref/(ref+1)) + new_score * (1/(ref+1)))   #careful with this
                hk_ref[i][hki] += 1


    #stores delta keys with highest score per byte
    for i in range(len(hk_score)):
        poss_k[i] = sorted(range(len(hk_score[i])), key = lambda sub: hk_score[i][sub])[-delta:] 

    #stores <ki> in XXXX-0000 format
    #admits table offset = 0
    for i in range(len(poss_k)):
        for key in poss_k[i]:
            high = key &0xf0
            if high not in all_part_k[i]:
                all_part_k[i].append(high)


    #print zone - to clear
    print("hk_score[0] - hk_ref[0]")
    for i in range(256):
        print("->" + str(i) + " - " + str(hk_score[0][i]) + " - " + str(hk_ref[0][i]))
    print("poss_k")
    print(poss_k)
    print("all_part_k")
    print(all_part_k)
    #print ______________
        





# Round 2 Attack Varables:

F = ffield.FField(8)

hk = [0 for y in range(16)]
hx = [0 for y in range(4)]
lk_score = [[0 for x in range(256)] for y in range(16)]
lk_ref = [[0 for x in range(256)] for y in range(16)]

fk = [-1 for y in range(16)]

part_k = [0 for x in range(16)]   #change name

def round_2_attack():

    l=0
    while(True):
        
        try:
            p,tables,scores  = read_files(l)
            l+=1
        except IOError:
            break

        for i in range(len(all_part_k)):
            part_k[i] = all_part_k[i][0]


        for low_hkA in range(0, 32-delta):
            for low_hkB in range(0, 32-delta):
                for low_hkC in range(0, 32-delta):
                    for low_hkD in range(0, 32-delta):
                        hk[0] = part_k[0] + low_hkA
                        hk[1] = part_k[1] + low_hkB
                        hk[2] = part_k[2] + low_hkC
                        hk[3] = part_k[3] + low_hkD
                        hk[4] = part_k[4] + low_hkA
                        hk[5] = part_k[5] + low_hkB
                        hk[6] = part_k[6] + low_hkC
                        hk[7] = part_k[7] + low_hkD
                        hk[8] = part_k[8] + low_hkA
                        hk[9] = part_k[9] + low_hkB
                        hk[10] = part_k[10] + low_hkC
                        hk[11] = part_k[11] + low_hkD
                        hk[12] = part_k[12] + low_hkA
                        hk[13] = part_k[13] + low_hkB
                        hk[14] = part_k[14] + low_hkC
                        hk[15] = part_k[15] + low_hkD


                        hx[0] = s[p[0] ^ hk[0]] ^ s[p[5] ^ hk[5]] ^ F.Multiply(2, s[p[10]^hk[10]]) ^ F.Multiply(3, s[p[15]^hk[15]]) ^ s[hk[15]] ^ part_k[2]
                        hx[1] = s[p[4] ^ hk[4]] ^ F.Multiply(2,s[p[9] ^ hk[9]]) ^ F.Multiply(3, s[p[14]^hk[14]]) ^ s[p[3]^hk[3]] ^ s[hk[14]] ^ part_k[1] ^ part_k[5]
                        hx[2] = F.Multiply(2,s[p[8] ^ hk[8]]) ^ F.Multiply(3,s[p[13] ^ hk[13]]) ^ s[p[2]^hk[2]] ^ s[p[7]^hk[7]] ^ s[hk[13]] ^ part_k[0] ^ part_k[4] ^ part_k[8] ^ 1
                        hx[3] = F.Multiply(3,s[p[12] ^ hk[12]]) ^ s[p[1]^hk[1]] ^ s[p[6]^hk[6]] ^ F.Multiply(2, s[p[11]^hk[11]]) ^ s[hk[12]] ^ part_k[3] ^ part_k[7] ^ part_k[11] ^ part_k[15]
     

                        for i in range(0,4):
                            line_x = (tables[(2-i)%4] + (hx[i]//delta)) % 64
                            new_score = scores[line_x]
                            for ki in range(0,4):
                                idx = (i*4 + ki*5)%16
                                
                                score = lk_score[idx][hk[idx]]
                                ref = lk_ref[idx][hk[idx]]

                                lk_score[idx][hk[idx]] =  score * (ref/(ref+1)) + new_score * (1/(ref+1)) #check this out / maybe use only sum not avg
                                lk_ref[idx][hk[idx]] += 1




    for i in range(len(lk_score)):
        fk[i] = sorted(range(len(lk_score[i])), key = lambda sub: lk_score[i][sub])[-1:]  # change this to use max() func



    #print_zone
    print("lk_score")
    print(lk_score)
    print("fk")
    print(fk)
    #------------



# Auxiliar functions

def read_files(l):
    
    meas_file = open("results/meas#" + str(l) + ".out", "r")
    vic_file = open("results/victim#" + str(l) + ".out", "r")

    first = vic_file.readline()
    first = first[:-2]

    plaintext = [int(i) for i in first.split('.')]
    tables = [int(i) for i in vic_file]
    scores = [int(i) for i in meas_file]

    meas_file.close()
    vic_file.close()

    return plaintext, tables, scores




round_1_attack()
round_2_attack()