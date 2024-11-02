#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void reduction_function(unsigned char* plain_text, unsigned char* cipher_text, int n, int chain_num)
{
    int bits_r, bits_q, i, j;
    unsigned int mask = 0, mask2 = 0;
    unsigned char xor[16] = {0,};
    int bin = chain_num, b = 0, digit = 0, xor_cnt = 15;

    while(bin > 0) {
        b += (bin % 2) << digit;
        digit++;
        bin >>= 1;
        if((digit != 0 && digit % 8 == 0) || bin == 0) {
            xor[xor_cnt--] = b;
            digit = 0;
            b = 0;
        }
    }

    for(i = 0; i < 16; i++)
        plain_text[i] = cipher_text[i] ^ xor[i];

    if(n % 8 != 0) {
        bits_q = n / 8 + 1;
        bits_r = n % 8;
    }
    else {
        bits_q = n / 8;
        bits_r = 8;
    }

    for(i = 0; i < 16 - bits_q; i++)
        plain_text[i] = 0;
        
    mask2 = 1 << (bits_r - 1);

    for(j = 0; j < bits_r; j++)
        mask += (1 << j);
    
    plain_text[i] &= mask;

    if(!(plain_text[i] & mask2))
        plain_text[i] += mask2;
}

int main(int argc, char** argv)
{
    freopen("rainbow", "w", stdout);

    int n = atoi(argv[1]);

    unsigned char key[16] = {0,};
    unsigned char tmp[16] = {0,};

    unsigned char plaintext[16] = {0,};

    unsigned char ciphertext[16];

    int chain_length = 1 << (n / 2);
    
    AES_KEY encrypt_key, decrypt_key;

    for(int i = (1 << (n - 1)); i < (1 << n); i += ((1 << (n - 1)) / chain_length)) {
        memcpy(plaintext, tmp, sizeof(tmp));
        memcpy(key, tmp, sizeof(tmp));

        int bin = i, b = 0, digit = 0, key_cnt = 15;

        while(bin > 0) {
            b += (bin % 2) << digit;
            digit++;
            bin >>= 1;
            if((digit != 0 && digit % 8 == 0) || bin == 0) {
                key[key_cnt--] = b;
                digit = 0;
                b = 0;
            }
        }
        fwrite(key, sizeof(char), 16, stdout);

        for(int j = 1; j < chain_length; j++) {
            AES_set_encrypt_key(key, 128, &encrypt_key);
            AES_ecb_encrypt(plaintext, ciphertext, &encrypt_key, AES_ENCRYPT);
            reduction_function(key, ciphertext, n, j);
        }

        AES_set_encrypt_key(key, 128, &encrypt_key);
        AES_ecb_encrypt(plaintext, ciphertext, &encrypt_key, AES_ENCRYPT);

        fwrite(ciphertext, sizeof(char), 16, stdout);
    }
    return 0;
}