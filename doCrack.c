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

void convert_encrypt(unsigned char* a, unsigned char* b)
{
    int i;
    unsigned char tmp;
    for(i = 0; i < 32; i += 2) {
        if(a[i] >= '0' && a[i] <= '9')
            tmp = (a[i] - '0') << 4;
        else
            tmp = (a[i] - 'a' + 10) << 4;

        if(a[i + 1] >= '0' && a[i + 1] <= '9')
            tmp += a[i + 1] - '0';
        else
            tmp += a[i + 1] - 'a' + 10;
        
        b[i / 2] = tmp;
    }
}

void convert_plain(unsigned char* a, unsigned char* b)
{
    int i;
    unsigned char tmp;
    for(i = 0; i < 31; i += 2) {
        tmp = a[i / 2] >> 4;
        if(tmp >= 0 && tmp <= 9)
            b[i] = tmp + '0';
        else
            b[i] = tmp - 10 + 'a';
        
        tmp = a[i / 2] & 0xf;
        if(tmp >= 0 && tmp <= 9)
            b[i + 1] = tmp + '0';
        else
            b[i + 1] = tmp - 10 + 'a';
    }
    b[32] = 0;
}

int main(int argc, unsigned char** argv)
{
    freopen("rainbow", "r", stdin);
    
    int n = atoi(argv[1]), flag = 0, ii, jj, cnt = 0;

    unsigned char key[16] = {0,};
    unsigned char tmp[16] = {0,};

    unsigned char plaintext[16] = {0,};

    unsigned char ciphertext[16];

    int chain_length = 1 << (n / 2);
    
    AES_KEY encrypt_key, decrypt_key;

    unsigned char inputs[2][50000][33], chaintext[2][50000][33];

    for(int i = 0; i < chain_length; i++) {
        unsigned char tmp_char[16];
        fread(tmp_char, sizeof(char), 16, stdin);
        convert_plain(tmp_char, inputs[0][i]);
        fread(tmp_char, sizeof(char), 16, stdin);
        convert_plain(tmp_char, inputs[1][i]);
        memcpy(chaintext[0][i], inputs[0][i], sizeof(chaintext[0][i]));
    }
    
    for(int i = 0; i < chain_length; i++) {
        if(strcmp(argv[2], inputs[1][i]) == 0) {
            flag = 1;
            ii = i, jj = chain_length;
            break;
        }
    }

    if(flag) {
        memcpy(chaintext[0][ii], inputs[0][ii], sizeof(inputs[0][ii]));
        convert_encrypt(chaintext[0][ii], key);
        for(int j = 0; j < jj; j++) {
            convert_plain(key, chaintext[0][ii]);
            AES_set_encrypt_key(key, 128, &encrypt_key);
            AES_ecb_encrypt(plaintext, ciphertext, &encrypt_key, AES_ENCRYPT);
            convert_plain(ciphertext, chaintext[1][ii]);
            cnt++;
            reduction_function(key, ciphertext, n, j + 1);
        }
        flag = 0;
        for(int j = 0; j < 32; j++) {
            if(!flag && chaintext[0][ii][j] == '0')
                continue;
            if(!flag) {
                flag = 1;
                printf("%c", chaintext[0][ii][j]);
                continue;
            }
            printf("%c", chaintext[0][ii][j]);
        }
        printf("\n%d\n", cnt);
        return 0;
    }
    else {
        flag = 0;
        for(int it = 1; it < chain_length - 1; it++) {
            memcpy(key, tmp, sizeof(tmp));
            for(int i = 0; i < chain_length; i++) {
                convert_encrypt(chaintext[0][i], key);
                AES_set_encrypt_key(key, 128, &encrypt_key);
                AES_ecb_encrypt(plaintext, ciphertext, &encrypt_key, AES_ENCRYPT);
                convert_plain(ciphertext, chaintext[1][i]);
                cnt++;
                if(strcmp(argv[2], chaintext[1][i]) == 0) {
                    flag = 1;
                    ii = i;
                    break;
                }
                reduction_function(key, ciphertext, n, it);
                convert_plain(key, chaintext[0][i + 1]);
            }
            if(flag)
                break;
        }
    }

    if(flag) {
        flag = 0;
        for(int j = 0; j < 32; j++) {
            if(!flag && chaintext[0][ii][j] == '0')
                continue;
            if(!flag) {
                flag = 1;
                printf("%c", chaintext[0][ii][j]);
                continue;
            }
            printf("%c", chaintext[0][ii][j]);
        }
        printf("\n");
    }
    else {
        printf("failure\n");
    }
    printf("%d\n", cnt);
    return 0;
}