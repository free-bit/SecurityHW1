#!/usr/bin/python
import sys
from vulnerable import *

#pad plain text with given pad_len if required
#return padded string
def padding(plain, pad_len):
  pads      = ['\x01','\x02','\x03','\x04','\x05','\x06','\x07', \
               '\x08','\x09','\x0A','\x0B','\x0C','\x0D','\x0E','\x0F']
  if(pad_len>0):
    return plain+pads[pad_len-1]*pad_len
  return plain

#xor two input lists of ints 
#return a string
def xor(ordDP, t):
  len_dp=len(ordDP)
  len_t=len(t)
  new_cipher_block = ''
  if(len_dp!=len_t):
    print "Error!"
    return None
  for i in range(len_dp):
    new_cipher_block += chr(ordDP[i] ^ t[i])
  return new_cipher_block

def attack(DP, cipher):
  possible_values = [] 
  for val in range(256):
    possible_values.append(val)

  t = [None]*16           #t will be max size of 16 and hold list of int vals
  orig_cipher = cipher[:] #copy original cipher, it will change during attack
  pad_len=0               #required pad length for DP

  for i in range(1, 17):
    c_index = 32-i                                          #from 31 to 16 
    t_index = 16-i                                          #from 15 to 0 
    init_val=cipher[c_index]                                #cipher[31->16]
    found = False                                           #true if one value other than itself is found
    #try all possible values
    for val in possible_values:                             
      cipher=cipher[:c_index]+chr(val)+cipher[c_index+1:]   #replacing cipher[29]: cipher[:29]+chr(val)+cipher[30:]
      if(decr(cipher)=="SUCCESS" and val!=ord(init_val)):   #check if padding correct
        t[t_index]=val^(i)                                  #t<-decrypted
        if(t_index>0):                                      #t_index==0 => terminate
          cipher_middle = ''                                #make replacement in cipher in the required parts
          for j in range(0, i):                             #set these parts of cipher using t
            cipher_middle+=chr(t[t_index+j]^(i+1))          
          cipher=cipher[:c_index]+cipher_middle+cipher[32:] #reform cipher
        found = True
        break;
    #if no value other than itself is found
    #this means padding ends from this point on 
    if not found:
      pad_len=i
      val = ord(init_val)
      t[t_index]=val^(i)                                    #t<-decrypted
      if(t_index>0):                                        #t_index==0 => terminate
        cipher_middle = ''                                  #make replacement in cipher in the required parts
        for j in range(0, i):                               #set these parts of cipher using t
          cipher_middle+=chr(t[t_index+j]^(i+1))          
        cipher=cipher[:c_index]+cipher_middle+cipher[32:]   #reform cipher
  #DP is non-padded string, pad it wrt pad_len found
  padded_DP=padding(DP, pad_len)
  #convert into list of int vals
  ordDP=[ord(each) for each in padded_DP]
  #use only required parts of t (from the end) 
  new_t_len=len(padded_DP)
  #drop unnecessary parts from the beginning
  new_t_start=len(t)-new_t_len
  #find changed part (from the end) of cipher block
  new_cipher_block = xor(ordDP, t[new_t_start:])
  #find length of changed and unchanged parts of block 2 (from the beginning)
  change_len=len(new_cipher_block)
  unchanged_len=16+16-change_len
  #combine
  new_ciphertext = orig_cipher[:unchanged_len]+new_cipher_block+orig_cipher[32:]
  # formatted_ciphertext = ''
  # for x in ciphertext:
  #   formatted_ciphertext+='\\x{}'.format(x.encode('hex'))
  # print formatted_ciphertext
  x=AES.new(key, AES.MODE_CBC, iv).decrypt(new_ciphertext)
  formatted = ''
  for each in x:
    if(ord(each)<32):
      formatted+='\\x{}'.format(each.encode('hex'))
    else:
      formatted+=each
  print formatted

def main(argv): 
    cipher=argv[0] #Read as byte string (there are unprintable chars)
    dp=argv[1]     #Read as string 
    attack(dp,cipher)

# NOTE: command line args have to be passed with enclosing quotes. 
# Otherwise special characters like space or tab is evaluated by terminal
if __name__ == "__main__":
    # print 'Number of arguments:', len(argv), 'arguments.'
    # print 'Argument List:', str(argv)
    main(sys.argv[1:])