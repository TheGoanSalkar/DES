from BitVector import *
import sys

class DES ():
# class constructor - when creating a DES object , the
# class ’s constructor is called and the instance variables
# are initialized

# note that the constructor specifies each instance of DES
# be created with a key file (str)
    def __init__ ( self , key):
    # within the constructor , initialize instance variables
    # these could be the s-boxes , permutation boxes , and
    # other variables you think each instance of the DES
    # class would need .
        self.key = open(key, "r").readlines()[0]
        self.expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

    # encrypt method declaration for students to implement
    # Inputs : message_file (str), outfile (str)
    # Return : void
    def encrypt ( self , message_file , outfile ):
    # encrypts the contents of the message file and writes
    # the ciphertext to the outfile
        final = BitVector(size = 0)

        round_keys = self.generate_round_keys()

        bv = BitVector(filename = message_file)
        while (bv.more_to_read):
            bitvec = bv.read_bits_from_file( 64 )
            if len(bitvec) < 64:
                bitvec.pad_from_right(64 - len(bitvec))
            if bitvec._getsize() > 0:
                [LE, RE] = bitvec.divide_into_two()
                
                for round_count in range(16):
                    # Expansion Permutation
                    newRE = RE.permute( self.expansion_permutation )
                    out_xor = newRE.__xor__( round_keys[round_count] )

                    # S-Box Substitution
                    output = self.substitute(out_xor)
                    
                    # P-Box Permutation
                    p_box = [15, 6, 19, 20, 28, 11, 27, 16,
                            0, 14, 22, 25, 4, 17, 30, 9,
                            1, 7, 23, 13, 31, 26, 2, 8,
                            18, 12, 29, 5, 21, 10, 3, 24]
                    RE_modified = output.permute(p_box)

                    temp = RE_modified.__xor__(LE)
                    LE = RE
                    RE = temp

                temp = LE
                LE = RE
                RE = temp 
                final += LE + RE
        
        final_hex = final.get_bitvector_in_hex()
        
        # print(temp)
        f = open(outfile, "w")
        f.write(final_hex)
        


    # decrypt method declaration for students to implement
    # Inputs : encrypted_file (str), outfile (str)
    # Return : void
    def decrypt ( self , encrypted_file , outfile ):
    # decrypts the contents of the encrypted_file and
    # writes the recovered plaintext to the outfile
        hex_str = open(encrypted_file, "r").readlines()[0]
        bv = BitVector(hexstring = hex_str)

        FILEOUT = open('temp.bin', 'wb')
        bv.write_to_file(FILEOUT)
        FILEOUT.close()
        
        final = BitVector(size = 0)
        
        round_keys = self.generate_round_keys()
        round_keys.reverse()

        bv = BitVector(filename = 'temp.bin')
        while (bv.more_to_read):
            bitvec = bv.read_bits_from_file( 64 )
            if len(bitvec) < 64:
                bitvec.pad_from_right(64 - len(bitvec))
            # print(bitvec)
            if bitvec._getsize() > 0:
                [LE, RE] = bitvec.divide_into_two()

                for round_count in range(16):
                    # Expansion Permutation
                    newRE = RE.permute( self.expansion_permutation )
                    out_xor = newRE.__xor__( round_keys[round_count] )

                    # S-Box Substitution
                    output = self.substitute(out_xor)
                    
                    # P-Box Permutation
                    p_box = [15, 6, 19, 20, 28, 11, 27, 16,
                            0, 14, 22, 25, 4, 17, 30, 9,
                            1, 7, 23, 13, 31, 26, 2, 8,
                            18, 12, 29, 5, 21, 10, 3, 24]
                    RE_modified = output.permute(p_box) # rmod = sbox_permute^LE

                    temp = RE_modified.__xor__(LE)
                    LE = RE
                    RE = temp

                temp = LE
                LE = RE
                RE = temp 
                final += LE + RE

        final_str = final.get_bitvector_in_ascii()

        f = open(outfile, "w", encoding="utf-8")
        f.write(final_str)    


    
    def generate_round_keys (self):
        key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                            9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                            62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                            13,5,60,52,44,36,28,20,12,4,27,19,11,3]
        key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                            3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                            54,29,39,50,44,32,47,43,48,38,55,33,52,
                            45,41,49,35,28,31]
        shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
        
        key = BitVector(textstring = self.key)
        key = key.permute(key_permutation_1)
        round_keys = []
        key = key.deep_copy()
        for round_count in range(16):
            [LKey, RKey] = key.divide_into_two()    
            shift = shifts_for_round_key_gen[round_count]
            LKey << shift
            RKey << shift
            key = LKey + RKey
            round_key = key.permute(key_permutation_2)
            round_keys.append(round_key)
        return round_keys
    


    def substitute( self, expanded_half_block ):
        s_boxes = {i:None for i in range(8)}

        s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
                    [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
                    [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
                    [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

        s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
                    [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
                    [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
                    [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

        s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
                    [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
                    [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
                    [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

        s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
                    [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
                    [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
                    [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

        s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
                    [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
                    [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
                    [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]  

        s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
                    [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
                    [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
                    [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

        s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
                    [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
                    [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
                    [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

        s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
                    [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
                    [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
                    [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]
        
        output = BitVector (size = 32)
        segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
        for sindex in range(len(segments)):
            row = 2*segments[sindex][0] + segments[sindex][-1]
            column = int(segments[sindex][1:-1])
            output[sindex*4:sindex*4+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
        return output       



    def encrypt_image (self, image_file, image_encrypt):
        bv = BitVector(filename = image_file)

        f1 = open(image_file, "rb")
        lines = f1.readlines()
        f1.close()

        f2 = open("image_without_header.ppm", "wb")
        for line in lines[3:]:
            f2.write(line)
        f2.close()

        # print(len(lines[0])) 3
        # print(len(lines[1])) 7
        # print(len(lines[2])) 4

        header = (lines[0] + lines[1] + lines[2]).decode('ascii')
        header_bv = BitVector(textstring = header)

        bv = BitVector(filename = "image_without_header.ppm")
        final = BitVector(size = 0)

        round_keys = self.generate_round_keys()

        while (bv.more_to_read):
            bitvec = bv.read_bits_from_file( 64 )
            if len(bitvec) < 64:
                bitvec.pad_from_right(64 - len(bitvec))
            if bitvec._getsize() > 0:
                [LE, RE] = bitvec.divide_into_two()
                
                for round_count in range(16):
                    # Expansion Permutation
                    newRE = RE.permute( self.expansion_permutation )
                    out_xor = newRE.__xor__( round_keys[round_count] )

                    # S-Box Substitution
                    output = self.substitute(out_xor)
                    
                    # P-Box Permutation
                    p_box = [15, 6, 19, 20, 28, 11, 27, 16,
                            0, 14, 22, 25, 4, 17, 30, 9,
                            1, 7, 23, 13, 31, 26, 2, 8,
                            18, 12, 29, 5, 21, 10, 3, 24]
                    RE_modified = output.permute(p_box)

                    temp = RE_modified.__xor__(LE)
                    LE = RE
                    RE = temp

                temp = LE
                LE = RE
                RE = temp 
                final += LE + RE
        
        final = header_bv + final
        
        FILEOUT = open(image_encrypt, 'wb')
        final.write_to_file(FILEOUT)  

# drive the encryption / decryption process
if __name__ == '__main__':
# example of construction of DES object instance
    cipher = DES ( key= sys . argv [3])
    
    if sys.argv[1] == '-e':
        cipher.encrypt(sys.argv[2], sys.argv[4])
    elif sys.argv[1] == '-d':
        cipher.decrypt(sys.argv[2], sys.argv[4])
    elif sys.argv[1] == '-i':
        cipher.encrypt_image(sys.argv[2], sys.argv[4])