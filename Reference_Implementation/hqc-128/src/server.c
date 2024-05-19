#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "api.h"
#include "parameters.h"

#define PORT 65432
#define BUFFER_SIZE 1024

unsigned char key2[SHARED_SECRET_BYTES];
unsigned char sk[SECRET_KEY_BYTES];
unsigned char pk[PUBLIC_KEY_BYTES];

void *handle_client(void *client_socket) {
    uint8_t u [VEC_N_SIZE_BYTES] = {0};
    uint8_t v [VEC_N1N2_SIZE_BYTES] = {0}; 
    unsigned char d[SHA512_BYTES];
    int sock = *((int *)client_socket);
    free(client_socket);
    char buffer[BUFFER_SIZE];
    int bytes_read;

    crypto_kem_keypair(pk, sk);
    FILE *fp = fopen("public_key.txt", "w");
    int result = fputs(pk, fp);
    fclose(fp);
    write(sock, pk, PUBLIC_KEY_BYTES);

    printf("Client connected.\n");

    while ((bytes_read = read(sock, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_read] = '\0';
        //printf("Buffer string is: %s", buffer);
        //printf("%s", "******************************************************");
        //crypto_kem_dec(key2, buffer, sk);
        // Retrieving u, v and d from ciphertext   
        FILE *fptr;
        fptr = fopen("secret_key.txt", "r");
        fgets(sk, SECRET_KEY_BYTES, fptr);
        fclose(fptr);

        hqc_ciphertext_from_string(u, v , d, buffer);

        // Retrieving pk from sk
        //unsigned char pk[PUBLIC_KEY_BYTES];
        //memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);

        //Decryting
        uint8_t m[VEC_K_SIZE_BYTES] = {0};
        hqc_pke_decrypt(m, u, v, sk);
        int r = strcmp(buffer, m);
        printf("%d\n\n\n", r);
        //printf("%s", "******************************************************");
        printf("Received: %s\n", m);
        //printf("%s", "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
        write(sock, m, strlen(m));
    }

    printf("Client disconnected.\n");
    close(sock);
    return NULL;
}

int main() {
    unsigned char pk[PUBLIC_KEY_BYTES];
    //unsigned char sk[SECRET_KEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES];
    unsigned char key1[SHARED_SECRET_BYTES];
    //unsigned char key2[SHARED_SECRET_BYTES];

    int server_socket, client_socket, *new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;

    //Generate key pair and save public key in a file
    //crypto_kem_keypair(pk, sk);
    //FILE *fp = fopen("public_key.txt", "w");
    //int result = fputs(pk, fp);
    //fclose(fp);
    FILE *fs = fopen("secret_key.txt", "w");
    int result2 = fputs(sk, fs);
    fclose(fs);

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Prepare the sockaddr_in structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Accept and handle incoming connections
    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len))) {
        new_sock = malloc(1);
        *new_sock = client_socket;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)new_sock) < 0) {
            perror("Could not create thread");
            free(new_sock);
            close(client_socket);
        }
        pthread_detach(thread_id);
    }

    if (client_socket < 0) {
        perror("Accept failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    close(server_socket);
    return 0;
}