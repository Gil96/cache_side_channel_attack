num_meas = 200
delta = 16
k = [[x for x in range(256)] for y in range(16)]


for l in range(0, num_meas):
    meas_name = "results/meas#" + str(l) + ".out"
    vic_name = "results/victim#" + str(l) + ".out"


    meas_file = open(meas_name, "r")
    vic_file = open(vic_name, "r")

    first = vic_file.readline()
    first = first[:-2]

    plaintext = [int(i) for i in first.split('.')]
    tables = [int(i) for i in vic_file]

    results = [int(i) for i in meas_file]

    meas_file.close()
    vic_file.close()

    #print( plaintext)

    u_lines = []
    for index, item in enumerate(results):
        if item < 500:
            u_lines.append(index) 

    # print (u_lines)
    
    for ti, table in enumerate (tables):
        for j in range(0,4):
            for hki in range(0,256):
                hacc = plaintext[ti + j*4] ^ hki
                # print("\t hki:" + str(hki) + " -> " + str(hacc))
                line_hacc = (table + (hacc//delta)) % 64
                # print("\t \t" + str(line_hacc))
                if line_hacc in u_lines:
                    k[ti + j*4][hki] = -1



# for i , ki in enumerate (k):
#     c=0
#     for elem in ki:
#         if elem != -1:
#             c+=1
#     print(str(i) + " - " +str(c//16))

for i , ki in enumerate (k):
    print (">> k" + str(i))
    for elem in ki:
        if elem != -1:
            print (elem)



