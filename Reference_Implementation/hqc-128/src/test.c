#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "api.h"
#include "parameters.h"

int main(){
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char sk[SECRET_KEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES];
    unsigned char key1[SHARED_SECRET_BYTES];
    unsigned char key2[SHARED_SECRET_BYTES];
    uint8_t u [VEC_N_SIZE_BYTES] = {0};
    uint8_t v [VEC_N1N2_SIZE_BYTES] = {0}; 
    unsigned char d[SHA512_BYTES];
    uint8_t message[1024]="test something";
    
    crypto_kem_keypair(pk, sk);
    FILE *fp = fopen("public_key_test.txt", "w");
    int result = fputs(pk, fp);
    fclose(fp);

    FILE *fptr;
    fptr = fopen("public_key_test.txt", "r");
    fgets(pk, PUBLIC_KEY_BYTES, fptr);
    fclose(fptr);

    crypto_kem_enc(ct, key1, pk, message);
    printf("%s", ct);
    printf("%s", "**********************************************************");

    // Retrieving u, v and d from ciphertext   
    hqc_ciphertext_from_string(u, v , d, ct);
    // Retrieving pk from sk
    //unsigned char pk[PUBLIC_KEY_BYTES];
    //memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);
    //Decryting
    uint8_t m[1024] = {0};
    hqc_pke_decrypt(m, u, v, sk);
    printf("%s", m);

}