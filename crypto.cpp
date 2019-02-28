#include <iostream>
#include <openssl/evp.h>
#include <string>
#include <vector>

using namespace std;

#define ENCRYPT 1
#define DECRYPT 0

bool compare(unsigned char *cipher1, unsigned char *cipher2, int length)
{
    for(int i=0; i<length; i++)
    {
        if(cipher1[i]!=cipher2[i])
            return false;
    }
    return true;
}

bool brute_force(FILE *keys, unsigned char *plain_text, unsigned char *cipher_text, int plain_text_size)
{
     /* Allow enough space in output buffer for additional block */
     unsigned char decrypted[32];
     unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     unsigned char key[17];
     int decrypted_length;
     EVP_CIPHER_CTX *ctx;
     while(!feof(keys)) //returns zero if eof
     {
            int key_size=0;
            char c=fgetc(keys);
            while(c!='\n' && c!=EOF && key_size<16)
            {
                key[key_size]=c;
                c=fgetc(keys);
                key_size++;
            }
            while(key_size<16)
            {
                key[key_size]='\0';
                key_size++;
            }
            key[key_size]='\0';
            // cout<<key<<endl;
            
            ctx=EVP_CIPHER_CTX_new();

            EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, ENCRYPT);

            OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
            OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

            EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, ENCRYPT);
            
            if (!EVP_CipherUpdate(ctx, decrypted, &decrypted_length, plain_text, plain_text_size)) 
            {
                cout<<"Error1"<<endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            if (!EVP_CipherFinal_ex(ctx, decrypted+decrypted_length, &decrypted_length)) 
            {
                cout<<"Error2"<<endl;
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            if(compare(decrypted, cipher_text, decrypted_length*2))
            {
                EVP_CIPHER_CTX_free(ctx);
                cout<<key<<endl;
                return true;
            }
     }
     EVP_CIPHER_CTX_free(ctx);
     return false;
}
int main(int argc, char const *argv[])
{
    if(argc<4)
    {
        cout<<"Missing file(s)"<<endl;
        exit(-1);
    }

    int plain_length=21;
    int cipher_length=32;
    
    unsigned char plain_text[plain_length], 
                  cipher_text[cipher_length];

    const char *plain_name=argv[1], 
               *cipher_name=argv[2], 
               *dict_name=argv[3];

    FILE *plain=fopen(plain_name, "r"), 
         *cipher=fopen(cipher_name, "r"), 
         *keys=fopen(dict_name, "r");

    fread(plain_text, sizeof(unsigned char), plain_length, plain);
    fread(cipher_text, sizeof(unsigned char), cipher_length, cipher);
    brute_force(keys, plain_text, cipher_text, plain_length);

    fclose(plain);
    fclose(cipher);
    fclose(keys);
    return 0;
}