import sys




def main():

    print 'Number of arguments:', len(sys.argv), 'arguments.'
    print 'Argument List:', str(sys.argv)



    with open('atk.c', 'r') as file:
        data = file.readlines()

    print(data[14])

    data[14] = 'N_MEAS_T 52 \n'



    # and write everything back
    # with open('atk.c', 'w') as file:
    #      file.writelines( data )



def change_I(file_name, I, )


main()