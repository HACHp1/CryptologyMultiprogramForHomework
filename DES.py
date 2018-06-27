def pad_number(number, pad_val):
    # if the input number is less that 32 bits
    # the code returns a 32 bit binary string
    # if the number is more than 32 bits it
    # returns a list of 32 bit intergers
    number = bin(number)[2:]
    startlen = len(number)

    if startlen < pad_val:

        padinglen = pad_val - startlen

        padstring = '0' * padinglen

        number = padstring + number

    elif startlen > pad_val:

        units = int(startlen / pad_val)
        # set up the padding for the left over
        # non-64 bit integer
        extrabit = pad_val - (startlen % pad_val)

        pading = '0' * extrabit

        binnumber = pading + number

        number = []
        for i in range(units + 1):
            number.append(binnumber[0:pad_val])
            binnumber = binnumber[pad_val:]

    return number


# convert text to a number by first splitting turning each character
# into a 1 byte number, then a binary string, then combining the strings
# into one long string which is converted into a single large decimal number
def text2num(text):
    result = ''

    for lett in text:
        number = ord(lett)

        result = result + pad_number(number, 8)

    return int(result, 2)


# convert a number to text using ascii. The number is converted to
# binary and split into bytes. Each byte is 1 character
def num2text(number):
    binnumberlist = pad_number(number, 8)
    text = ''

    for i, binnumber in enumerate(binnumberlist):
        number = int(binnumber, 2)
        letter = chr(number)
        text = text + letter

    return text


# Converts a string into a list of strings of length
# defined by block_size
def string2blocks(string, block_size):
    # these sections are to show the crazy bug
    # print 'Input:-'
    # print string
    # pad the string if it won't split into nice convinent blocks
    if len(string) % block_size != 0:
        extension = ' ' * (block_size - (len(string) % block_size))
        string = string + extension

    # scroll through and build the blocks saving them when they're
    # long enough
    block = ''
    blocks = []
    for i, lett in enumerate(string):

        block = block + lett

        if (len(block) == block_size):
            blocks.append(block)
            block = ''

    # these sections are to show you the wierd bug
    # print 'Output:-'
    # print blocks
    # return the list of strings
    return blocks


def ROL(number, rotdist, bit_length):
    number = bin(number)[2:]

    a = number.zfill(bit_length)

    # loop over the number of rotations needed
    for i in range(rotdist):
        # perform one rotation at a time
        b = ''
        # do the loop first. If it were not
        # for the looping we could use pythons
        # internal bitwise shift tools
        b = a[1:bit_length] + a[0]

        # alter a to ensure perminance over
        # all the shifts in the code
        # a = int(b, 2)
        a = b

    # print(a)
    return int(a, 2)


#######################################
### Start of DES specific functions ###
#######################################

def Initial_pert(block):
    # initial permutation indicies

    block = pad_number(block, 64)

    IP = (58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7)

    initial_pertubation = ''
    for i in IP:
        initial_pertubation += block[i - 1]

    return initial_pertubation


def Final_pert(block):
    # Final permuation indicies
    FP = (40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25)

    final_pertubation = ''
    for i in FP:
        final_pertubation += block[i - 1]

    return final_pertubation


# The expansion function, takes in binary and outputs decimal
def Expansion_func(half_block):
    E = (32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1)

    result = ''
    for i in E:
        result += half_block[i - 1]

    result_int = int(result, 2)
    return result_int


# Permutation function, take a binary and outputs a decimal
def Perm_func(to_perm):
    # the permutation intigers
    P = (16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25)

    result = ''

    for i in P:
        result += to_perm[i - 1]

    return int(result, 2)


# Permutation table 1, takes in a number, converts it into a binary string
# and does the pertubation, returns two 28 bit binary strings
def Perm_choice_1(Key):
    PC_1L = (57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19, 11, 3, 60, 52, 44, 36)

    PC_1R = (63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4)

    # convert the key into a binary string
    Key_input = pad_number(Key, 64)

    result_left = ''
    result_right = ''
    for i, pc1 in enumerate(PC_1L):
        result_left += Key_input[PC_1L[i] - 1]
        result_right += Key_input[PC_1R[i] - 1]

    return [int(result_left, 2), int(result_right, 2)]


# Permutates choice table 2
def Perm_choice_2(left_side, right_side):
    PC_2 = (14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32)

    PC2_string = pad_number(left_side, 28) + pad_number(right_side, 28)

    result = ''
    for i in PC_2:
        result += PC2_string[i - 1]

    return result


# The s boxes function
def DES_S_boxes(s_input, box_no):
    S = (([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
          [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
          [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
          [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13])
         , ([15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9])
         , ([10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12])
         , ([7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14])
         , ([2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3])
         , ([12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13])
         , ([4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12])
         , ([13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]))

    S_result = S[box_no][int(s_input[0] + s_input[-1], 2)][int(s_input[1:5], 2)]

    return pad_number(S_result, 4)


def get_rots(round_no):
    rot_number = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    return rot_number[round_no]


# The fistal function. Takes in a binary left side and returns
# an intiger result
def Fistel_func(Fist_input, sub_key):
    Fist_input = pad_number(Fist_input, 32)

    expanded = Expansion_func(Fist_input)

    into_the_Ses = expanded ^ sub_key

    into_the_Ses = pad_number(into_the_Ses, 48)

    S_box_result = ''

    for i in range(8):
        S_box_result += DES_S_boxes(into_the_Ses[(i * 6):((i * 6) + 6)], i)

    Fistel_result = Perm_func(S_box_result)

    return Fistel_result

def Gen_subkeys(Key):
    [left_side, right_side] = Perm_choice_1(Key)

    subkeys = []

    for round_no in range(16):
        rots = get_rots(round_no)

        left_side = ROL(left_side, rots, 28)
        right_side = ROL(right_side, rots, 28)

        subkey = Perm_choice_2(left_side, right_side)

        subkeys.append(int(subkey, 2))

    return subkeys


# encrypts a block
def DES_encrypt_one_block(block_num, subkeys):
    # Do the initial pertubation
    IP_result = Initial_pert(block_num)

    # Seperate out the two sides of the blocks
    left_side = int(IP_result[0:32], 2)
    right_side = int(IP_result[32:], 2)

    for round_no in range(16):
        # pull out the subkey for this round
        sub_key = subkeys[round_no]
        # Do the Feistel box
        Fistel_result = Fistel_func(right_side, sub_key)

        # XOR Feistel result with the left side
        left_side ^= Fistel_result

        # Switch the two sides arround
        [right_side, left_side] = [left_side, right_side]

    # undo the last switcharoo and recombine the two halves
    end_of_rounds = pad_number(right_side, 32) + pad_number(left_side, 32)

    # Do the final permutation function
    encrypted = int(Final_pert(end_of_rounds), 2)

    return encrypted


# decrypts a block
def DES_decrypt_one_block(block_num, subkeys):
    # Do the reverse of the final pertubation, the initail pertubation
    IP_result = Initial_pert(block_num)

    # Seperate out the two sides of the blocks
    left_side = int(IP_result[0:32], 2)
    right_side = int(IP_result[32:], 2)

    for round_no in range(16):
        # pull out the subkey for this round
        sub_key = subkeys[15 - round_no]
        # Do the Feistel box
        Fistel_result = Fistel_func(right_side, sub_key)

        # XOR Feistel result with the left side
        left_side ^= Fistel_result

        # Switch the two sides arround
        [right_side, left_side] = [left_side, right_side]

    # undo the last switcharoo and recombine the two halves
    end_of_rounds = pad_number(right_side, 32) + pad_number(left_side, 32)

    # Do the final permutation function
    decrypted = int(Final_pert(end_of_rounds), 2)

    return decrypted


##############################
### The main two functions ###
##############################

# Do the whole DES encryption process
def DES_encrypt(message, Password):
    # convert the password into a numerical key
    Key = text2num(Password)
    # generate the subkeys
    subkeys = Gen_subkeys(Key)

    # Split the message into blocks
    block_size = 8
    blocks = string2blocks(message, block_size)

    cypher = ''
    for block in blocks:
        block_num = text2num(block)

        encrypted = DES_encrypt_one_block(block_num, subkeys)

        cypher += pad_number(encrypted, 64)

    encrypted_result = int(cypher, 2)

    return encrypted_result


def DES_decrypt(encrypted_result, Password):
    # convert the password into a numerical key
    Key = text2num(Password)
    # generate the subkeys
    subkeys = Gen_subkeys(Key)

    # Convert the encrypted number into binary of a length that divides into
    # 64 bit blocks
    encrypted_binary = pad_number(encrypted_result,
                                  len(bin(encrypted_result)[2:]) + (len(bin(encrypted_result)[2:]) % 64))

    # This for loop cuts the binary string into 64 bit blocks
    blocks = []
    for block_no in range(int(len(encrypted_binary) / 64)):
        block = encrypted_binary[(block_no * 64):((block_no * 64) + 64)]

        blocks.append(int(block, 2))

    decrypted_blocks = []

    # The blocks are then decrypted
    for block in blocks:
        decrypted_block = DES_decrypt_one_block(block, subkeys)

        decrypted_blocks.append(decrypted_block)

    # print(stop)
    # Convert the result into plain text
    text = ''
    for block in decrypted_blocks:
        text += num2text(block)

    return text

if __name__=='__main__':
    message = 'Network Security'
    Password = 'WilliamS'
    encrypted_result = DES_encrypt(message, Password)
    print('%x'%encrypted_result)
    plain_text = DES_decrypt(encrypted_result, Password)
    print(plain_text)

    key = 'WilliamS'
    msg = 'Network Security'


'''
明文：(16个字节，128bit，用16进制表示)
      4E6574776F726B205365637572697479  
密钥：(8个字节，64bit，用16进制表示)
      57696C6C69616D53  
密文：(16个字节，128bit，用16进制表示)
     ECB模式：958920B1358EF1972B9EE4548DC08E8A
'''
