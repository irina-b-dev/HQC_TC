#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/err.h>
#include "api.h"
#include "parameters.h"


#define BUFFER_SIZE 1024

void benchmark_my_algorithm() {
    unsigned char message[] = "Benchmarking HQC";
    unsigned char encrypted[CIPHERTEXT_BYTES];
    unsigned char decrypted[BUFFER_SIZE];
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char sk[SECRET_KEY_BYTES];
    unsigned char ss[SHARED_SECRET_BYTES];

    struct timespec start, end;
    double time_spent;

    // Key generation

    if (crypto_kem_keypair(pk, sk) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return;
    }

    // Encryption

    if (crypto_kem_enc(encrypted, ss, pk, message) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return;
    }

    // Decryption

    if (crypto_kem_dec(ss, encrypted, sk) != 0) {
        //fprintf(stderr, "Decryption failed\n");
        //return;
    }

}


void print_memory_usage() {
    FILE* status = fopen("/proc/self/status", "r");
    if (status == NULL) {
        perror("fopen");
        return;
    }
    printf("Memory and Process Information:\n");
    char line[256];
    while (fgets(line, sizeof(line), status) != NULL) {
         if (strncmp(line, "VmRSS:", 6) == 0) {
            printf("Memory usage: ");
            // Convert to MB
            int memory;
            sscanf(line + 6, "%d", &memory);
            memory /= 1024;
            printf("%d MB\n", memory);
            break;
            printf("%s", line);
            break;
        }
        printf("%s", line);
    }
    fclose(status);
}



int main() {
    
    benchmark_my_algorithm();
    print_memory_usage();
    
    // FILE* status = fopen("/proc/self/status", "r");
    // if (status == NULL) {
    //     perror("fopen");
    //     return 1;
    // }
    // printf("Memory usage: ");
    // char line[128];
    // while (fgets(line, 128, status) != NULL) {
    //     if (strncmp(line, "VmRSS:", 6) == 0) {
    //         // Convert to MB
    //         int memory;
    //         sscanf(line + 6, "%d", &memory);
    //         memory /= 1024;
    //         printf("%d MB\n", memory);
    //         break;
    //         printf("%s", line);
    //         break;
    //     }
    // }
    // fclose(status);
    return 0;
}