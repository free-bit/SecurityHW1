from Crypto.Cipher import AES
key = "1tbs23j1qdfdpoer"
iv = "1234567891011121"

def decr(ciphertext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return ispkcs7(cipher.decrypt(ciphertext))

def ispkcs7(plaintext):
  l = len(plaintext)
  c = ord(plaintext[l-1])                       
  if (c > 16) or (c < 1):
    return "ERROR"
  if plaintext[l-c:] != chr(c)*c:
    return "ERROR"
  return "SUCCESS"

def encr(plaintext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  ciphertext = cipher.encrypt(pkcs7(plaintext))
  return ciphertext

def pkcs7(plaintext):
  padbytes = 16 - len(plaintext) % 16
  pad = padbytes * chr(padbytes)
  return plaintext + pad
