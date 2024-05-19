#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "api.h"
#include "parameters.h"

#define PORT 65432
#define BUFFER_SIZE 1024

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main() {
    unsigned char key1[SHARED_SECRET_BYTES];
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES];

    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        handle_errors("Socket creation error");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        handle_errors("Invalid address / Address not supported");
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_errors("Connection failed");
    }

    printf("Connected to server at 127.0.0.1:%d\n", PORT);

    // Receive public key from server
    if (read(sock, pk, PUBLIC_KEY_BYTES) != PUBLIC_KEY_BYTES) {
        handle_errors("Failed to receive public key");
    }

    while (1) {
        printf("Enter message to send (or 'exit' to quit): ");
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;  // Remove newline character

        if (strcmp(message, "exit") == 0) {
            break;
        }

        // Encrypt the message
        if (crypto_kem_enc(ct, key1, pk, message) != 0) {
            handle_errors("Encryption failed");
        }

        // Send the ciphertext
        if (send(sock, ct, CIPHERTEXT_BYTES, 0) != CIPHERTEXT_BYTES) {
            handle_errors("Failed to send ciphertext");
        }

        // Receive response from server
        int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
        if (bytes_received < 0) {
            handle_errors("Read error");
        }

        //buffer[bytes_received] = '\0';
        //printf("Received from server: %s\n", buffer);
    }

    close(sock);
    printf("Connection closed.\n");
    return 0;
}