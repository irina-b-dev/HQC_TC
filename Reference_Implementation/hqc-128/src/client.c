#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "rng.h"
#include "parameters.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define PORT 65432
#define BUFFER_SIZE 1024



int main() {
    unsigned char key1[SHARED_SECRET_BYTES];
    unsigned char key2[SHARED_SECRET_BYTES];
    unsigned char pk[PUBLIC_KEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES];

    //FILE *fptr;
    //fptr = fopen("public_key.txt", "r");
    //fgets(pk, PUBLIC_KEY_BYTES, fptr);
    //fclose(fptr);

    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    uint8_t message[BUFFER_SIZE];

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server at 127.0.0.1:%d\n", PORT);
    read(sock, pk, PUBLIC_KEY_BYTES);
    while (1) {
        printf("Enter message to send (or 'exit' to quit): ");
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;  // Remove newline character

        if (strcmp(message, "exit") == 0) {
            break;
        }
        crypto_kem_enc(ct, key1, pk, message);

        send(sock, ct, strlen(ct), 0);
        int bytes_received = read(sock, buffer, BUFFER_SIZE - 1);
        buffer[bytes_received] = '\0';
        printf("Received from server: %s\n", buffer);
    }

    close(sock);
    printf("Connection closed.\n");
    return 0;
}