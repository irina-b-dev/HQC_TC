#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "benchmark.h"
#include "api.h"
#include "parameters.h"

#define BUFFER_SIZE 1024
#define num_run 10000

// Function to measure time taken for key generation, encryption, and decryption of HQC
void benchmark_my_algorithm() {
    clock_t start, end;
    double cpu_time_used;

    unsigned char message[] = "Benchmarking HQC";
    unsigned char encrypted[CIPHERTEXT_BYTES];
    unsigned char decrypted[BUFFER_SIZE];
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char sk[SECRET_KEY_BYTES];
    unsigned char ss[SHARED_SECRET_BYTES];
    int i=0;

    // Key generation
    start = clock();
    while(i < num_run){
    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("HQC Key Generation Time: %f seconds\n", cpu_time_used);

    // Encryption
    i = 0;
    start = clock();
    while(i < num_run){
    if (crypto_kem_enc(encrypted, ss, pk, message) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("HQC Encryption Time: %f seconds\n", cpu_time_used);

    // Decryption
    i = 0;
    start = clock();
    while(i < num_run){
        // memcpy(ss2, ss, SHARED_SECRET_BYTES);
        // memcpy(encrypted2, encrypted, CIPHERTEXT_BYTES);
        // memcpy(sk2, sk, SECRET_KEY_BYTES);
    if (crypto_kem_dec(ss, encrypted, sk) != 0) {
        //fprintf(stderr, "Decryption failed\n");
        //return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("HQC Decryption Time: %f seconds\n", cpu_time_used);
}

void benchmark_rsa() {
    clock_t start, end;
    double cpu_time_used;

    unsigned char message[] = "Benchmarking RSA";
    unsigned char encrypted[128];
    unsigned char decrypted[128];
    int i=0;
    int encrypted_length;
    int decrypted_length;

    RSA *rsa_keypair = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    // Key generation
    start = clock();
    while(i < num_run){
    if (RSA_generate_key_ex(rsa_keypair, 1024, bn, NULL) != 1) {
        fprintf(stderr, "RSA key generation failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("RSA Key Generation Time: %f seconds\n", cpu_time_used);

    // Encryption
    i = 0;
    start = clock();
    while(i<num_run){
    encrypted_length = RSA_public_encrypt(strlen((char*)message) + 1, message, encrypted, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        fprintf(stderr, "RSA encryption failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("RSA Encryption Time: %f seconds\n", cpu_time_used);

    // Decryption
    i = 0;
    start = clock();
    while(i < num_run){
    decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        fprintf(stderr, "RSA decryption failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("RSA Decryption Time: %f seconds\n", cpu_time_used);

    RSA_free(rsa_keypair);
    BN_free(bn);
}

void benchmark_dsa() {
    clock_t start, end;
    double cpu_time_used;

    unsigned char message[] = "Benchmarking DSA";
    unsigned char signature[128];
    unsigned int sig_len;
    DSA *dsa = DSA_new();
    int i=0;

    // Key generation
    start = clock();
    while(i < num_run){
    if (DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "DSA parameter generation failed\n");
        return;
    }
    if (DSA_generate_key(dsa) != 1) {
        fprintf(stderr, "DSA key generation failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("DSA Key Generation Time: %f seconds\n", cpu_time_used);

    // Signing
    i = 0;
    start = clock();
    while(i <num_run){
    if (DSA_sign(0, message, strlen((char*)message), signature, &sig_len, dsa) != 1) {
        fprintf(stderr, "DSA signing failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("DSA Signing Time: %f seconds\n", cpu_time_used);

    // Verification
    i=0;
    start = clock();
    while(i<num_run){
    if (DSA_verify(0, message, strlen((char*)message), signature, sig_len, dsa) != 1) {
        fprintf(stderr, "DSA verification failed\n");
        return;
    }
    i++;
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("DSA Verification Time: %f seconds\n", cpu_time_used);

    DSA_free(dsa);
}


int main() {
    printf("Benchmarking My Algorithm:\n");
    benchmark_my_algorithm();
    printf("\n");

    printf("Benchmarking RSA:\n");
    benchmark_rsa();
    printf("\n");

    printf("Benchmarking DSA:\n");
    benchmark_dsa();
    printf("\n");

    return 0;
}