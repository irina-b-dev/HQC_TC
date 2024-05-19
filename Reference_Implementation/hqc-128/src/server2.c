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

unsigned char sk[SECRET_KEY_BYTES];
unsigned char pk[PUBLIC_KEY_BYTES];

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void *handle_client(void *client_socket) {
    int sock = *((int *)client_socket);
    free(client_socket);
    unsigned char buffer[CIPHERTEXT_BYTES];
    unsigned char ss[SHARED_SECRET_BYTES];
    int bytes_read;
    uint8_t message[BUFFER_SIZE];
    uint8_t u [VEC_N_SIZE_BYTES] = {0};
    uint8_t v [VEC_N1N2_SIZE_BYTES] = {0};
    uint8_t m [1024] = {0}; 
    unsigned char d[SHA512_BYTES];

    printf("Client connected.\n");

    // Send the public key to the client
    if (write(sock, pk, PUBLIC_KEY_BYTES) != PUBLIC_KEY_BYTES) {
        handle_errors("Failed to send public key");
    }

    while ((bytes_read = read(sock, buffer, CIPHERTEXT_BYTES)) > 0) {
        printf("Encrypted message: %s\n", buffer);
        hqc_ciphertext_from_string(u, v , d, buffer);
        //if (crypto_kem_dec(ss, buffer, sk, message) != 0) {
        //    handle_errors("Decryption failed");
        //}
        hqc_pke_decrypt(message, u, v, sk);

        //ss[SHARED_SECRET_BYTES] = '\0';
        message[BUFFER_SIZE - 1] = '\0';
        printf("Received: %s\n", message);

        // Echo the decrypted message back to the client
        if (write(sock, message, BUFFER_SIZE) != BUFFER_SIZE) {
            handle_errors("Failed to send response");
        }
    }

    printf("Client disconnected.\n");
    close(sock);
    return NULL;
}

int main() {
    int server_socket, client_socket, *new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;

    // Generate the key pair
    if (crypto_kem_keypair(pk, sk) != 0) {
        handle_errors("Key pair generation failed");
    }

    // Create socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        handle_errors("Socket creation failed");
    }

    // Prepare the sockaddr_in structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_errors("Bind failed");
    }

    // Listen
    if (listen(server_socket, 5) < 0) {
        handle_errors("Listen failed");
    }

    printf("Server listening on port %d\n", PORT);

    // Accept and handle incoming connections
    while ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len))) {
        new_sock = malloc(1);
        *new_sock = client_socket;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)new_sock) < 0) {
            handle_errors("Could not create thread");
        }
        pthread_detach(thread_id);
    }

    if (client_socket < 0) {
        handle_errors("Accept failed");
    }

    close(server_socket);
    return 0;
}