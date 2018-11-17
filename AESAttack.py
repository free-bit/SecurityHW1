#!/usr/bin/python
import sys
from vulnerable import *

def padding(plain):
  pads      = ['\x01','\x02','\x03','\x04','\x05','\x06','\x07', \
               '\x08','\x09','\x0A','\x0B','\x0C','\x0D','\x0E','\x0F']
  plain_len = len(plain)
  pad_len   = 16 - plain_len
  return plain+pads[pad_len-1]*pad_len

def xor(t, plaintext, new_cipher_block):
  new_cipher_block = list(new_cipher_block)
  for i in range(16):
    if(t[i]!=None):
      new_cipher_block[i] = t[i] ^ ord(plaintext[i])
  return ''.join(chr(e) for e in new_cipher_block)

def attack(plain, cipher):
  possible_values = [] 
  for val in range(256):
    possible_values.append(val)

  t = [None]*16

  orig_cipher = cipher[:]
  #orig_cipher_block = cipher[16:32]

  for i in range(1, 17):
    c_index = 32-i                                          #From 31 to 16 
    t_index = 16-i                                          #From 15 to 0 
    init_val=cipher[c_index]                                #CipherText[31->16]
    for val in possible_values:                             
      cipher=cipher[:c_index]+chr(val)+cipher[c_index+1:]   #Replacing cipher[29]: cipher[:29]+chr(val)+cipher[30:]
      if(decr(cipher)=="SUCCESS" and val!=ord(init_val)):   #Check if padding correct
        print val
        t[t_index]=val^(i)                                  #t<-decrypted
        if(t_index>0):                                      #t_index==0 => terminate
          cipher_middle = ''                                #Make replacement in cipher in the required parts
          for j in range(0, i):                             #Set these parts of cipher using t
            cipher_middle+=chr(t[t_index+j]^(i+1))          
          cipher=cipher[:c_index]+cipher_middle+cipher[32:] #Reform cipher
        break;
  print t
  new_middle_block=xor(t, pkcs7(plain), orig_cipher[16:32])
  new_cipher=orig_cipher[:16]+new_middle_block+orig_cipher[32:]
  print len(new_cipher)
  decrytion = AES.new(key, AES.MODE_CBC, iv)
  print decrytion.decrypt(new_cipher)
  # init_val=cipher[31]
  # for val in possible_values:
  #   cipher=cipher[:31]+chr(val)+cipher[32:]
  #   if(decr(cipher)=="SUCCESS" and val!=ord(init_val)):
  #     # print val
  #     t[15]=val^1
  #     cipher=cipher[:31]+chr(t[15]^2)+cipher[32:]
  #     init_val=cipher[30]
  #     for val2 in possible_values:
  #       cipher=cipher[:30]+chr(val2)+cipher[31:]
  #       if(decr(cipher)=="SUCCESS" and val2!=ord(init_val)):
  #         # print val2
  #         t[14]=val2^2
  #         cipher=cipher[:30]+chr(t[14]^3)+chr(t[15]^3)+cipher[32:]
  #         init_val=cipher[29]
  #         for val3 in possible_values:
  #           cipher=cipher[:29]+chr(val3)+cipher[30:]
  #           if(decr(cipher)=="SUCCESS" and val3!=ord(init_val)):
  #             # print val3
  #             t[13]=val3^3
  #             cipher=cipher[:29]+chr(t[13]^4)+chr(t[14]^4)+chr(t[15]^4)+cipher[32:]
  #             init_val=cipher[28]
  #             for val4 in possible_values:
  #               cipher=cipher[:28]+chr(val4)+cipher[29:]
  #               if(decr(cipher)=="SUCCESS" and val4!=ord(init_val)):
  #                 # print val4
  #                 t[12]=val4^4
  #                 cipher=cipher[:28]+chr(t[12]^5)+chr(t[13]^5)+chr(t[14]^5)+chr(t[15]^5)+cipher[32:]
  #                 init_val=cipher[27]
  #                 for val5 in possible_values:
  #                   cipher=cipher[:27]+chr(val5)+cipher[28:]
  #                   if(decr(cipher)=="SUCCESS" and val5!=ord(init_val)):
  #                     print val5
  #                     t[11]=val5^5
  #                     print t

  # print "Original:"
  # for each in cipher:
  #   print ord(each),
  # print ""


def main(argv):
    # print 'Number of arguments:', len(argv), 'arguments.'
    # print 'Argument List:', str(argv)
    # plain="This is a top secret. This is a top secret."
    plain="\xdd"*16+"\xee"*32+"\xff"*10
    print "Plain:"+str(len(plain))
    padded_plain=pkcs7(plain)
    print "Plain:"+str(len(padded_plain))
    cipher=encr(plain)
    print "Cipher:"+str(len(cipher))
    attack("abc",cipher)

if __name__ == "__main__":
    main(sys.argv[1:])