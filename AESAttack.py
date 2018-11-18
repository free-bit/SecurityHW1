#!/usr/bin/python
import sys
from vulnerable import *

def padding(plain):
  pads      = ['\x01','\x02','\x03','\x04','\x05','\x06','\x07', \
               '\x08','\x09','\x0A','\x0B','\x0C','\x0D','\x0E','\x0F']
  plain_len = len(plain)
  pad_len   = 16 - plain_len
  return plain+pads[pad_len-1]*pad_len

def xor(ordDP, ordPlain, ordOCB2):
  new_cipher_block = ''
  for i in range(16):
    new_cipher_block += chr(ordDP[i] ^ ordPlain[i] ^ ordOCB2[i])
  return new_cipher_block


def attack(DP, cipher):
  possible_values = [] 
  for val in range(256):
    possible_values.append(val)

  orig_plain = [None]*16
  orig_cipher = cipher[:]
  orig_cipher_block_2 = orig_cipher[16:32]

  for i in range(1, 17):
    c_index     = 32-i                                      #From 31 to 16 
    plain_index = 16-i                                      #From 15 to 0 
    init_val=cipher[c_index]                                #CipherText[31->16]
    found = False                                           #true if one value other than itself is found
    #try all possible values
    for val in possible_values:                             
      cipher=cipher[:c_index]+chr(val)+cipher[c_index+1:]                      #Replacing cipher[29]: cipher[:29]+chr(val)+cipher[30:]
      if(decr(cipher)=="SUCCESS" and val!=ord(init_val)):                      #Check if padding correct
        orig_plain[plain_index]=ord(orig_cipher_block_2[plain_index])^val^(i)  #orig_plain<-decrypted
        if(plain_index>0):                                                     #plain_index==0 => terminate
          cipher_middle = ''                                                   #Make replacement in cipher in the required parts
          for j in range(0, i):                                                #Set these parts of cipher using orig_plain
            cipher_middle+=chr(orig_plain[plain_index+j]\
                           ^ord(orig_cipher_block_2[plain_index+j])\
                           ^(i+1))          
          cipher=cipher[:c_index]+cipher_middle+cipher[32:]                    #Reform cipher
        found = True
        break;
    #if no value other than itself is found
    if not found:
      val = ord(init_val)
      orig_plain[plain_index]=ord(orig_cipher_block_2[plain_index])^val^(i)  #orig_plain<-decrypted
      if(plain_index>0):                                                     #plain_index==0 => terminate
        cipher_middle = ''                                                   #Make replacement in cipher in the required parts
        for j in range(0, i):                                                #Set these parts of cipher using orig_plain
          cipher_middle+=chr(orig_plain[plain_index+j]\
                         ^ord(orig_cipher_block_2[plain_index+j])\
                         ^(i+1))          
        cipher=cipher[:c_index]+cipher_middle+cipher[32:]                    #Reform cipher

  #orig_plain holds list of int vals for each char in original plain text
  #DP is non-padded string
  padded_DP=pkcs7(DP)
  #convert into list of int vals
  ordDP = [ord(each) for each in padded_DP]
  #orig_cipher_block_2 holds string of this block
  ordOCB2 = [ord(each) for each in orig_cipher_block_2]
  new_cipher_block = xor(ordDP, orig_plain, ordOCB2)
  #combine
  ciphertext = orig_cipher[:16]+new_cipher_block+orig_cipher[32:]

  #Original plain text
  orig_plaintext = ''
  for each in orig_plain:
    if(each<31):
      orig_plaintext+='\\x{}'.format(chr(each).encode('hex'))
    else:
      orig_plaintext+=chr(each)
  print orig_plaintext

  formatted_ciphertext = ''
  for x in ciphertext:
    formatted_ciphertext+='\\x{}'.format(x.encode('hex'))
  print formatted_ciphertext
  print AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)

def main(argv): 
    # print 'Number of arguments:', len(argv), 'arguments.'
    # print 'Argument List:', str(argv)
    cipher=argv[0] #Read as byte string (there are unprintable chars)
    dp=argv[1] 		 #Read as string 
    print len(cipher)
    print len(dp)
    attack(dp,cipher)

# NOTE: Commandline args have to be passed with enclosing quotes. 
# Otherwise special characters like space or tab is evaluated by terminal
if __name__ == "__main__":
    main(sys.argv[1:])