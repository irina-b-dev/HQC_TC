#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define EVE_PORT 9090
#define BOB_PORT 8080

// Select connection to Bob or Eve
#define SERVER_PORT EVE_PORT
//BOB_PORT

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

DH *load_dh_params(const char *file_name) {
    DH *dh = NULL;
    FILE *param_file = fopen(file_name, "r");

    if (!param_file) {
        perror("Unable to open DH parameter file");
        exit(EXIT_FAILURE);
    }

    dh = PEM_read_DHparams(param_file, NULL, NULL, NULL);
    fclose(param_file);

    if (!dh) {
        fprintf(stderr, "Error reading DH parameters from file\n");
        exit(EXIT_FAILURE);
    }

    return dh;
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    const BIGNUM *pub_key = NULL, *priv_key = NULL;
    DH *dh = load_dh_params("dhparams.pem");

    if (1 != DH_generate_key(dh)) {
        handleErrors();
    }

    DH_get0_key(dh, &pub_key, &priv_key);
    char *pub_key_hex = BN_bn2hex(pub_key);
    printf("Alice's Public Key: %s\n", pub_key_hex);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\nSocket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address / Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    send(sock, pub_key_hex, strlen(pub_key_hex) + 1, 0);

    char buffer[2048] = {0};
    read(sock, buffer, 2048);
    printf("Received Bob's Public Key: %s\n", buffer);

    BIGNUM *bob_pub_key = NULL;
    BN_hex2bn(&bob_pub_key, buffer);

    unsigned char *secret = malloc(DH_size(dh));
    int secret_size = DH_compute_key(secret, bob_pub_key, dh);
    if (secret_size < 0) {
        handleErrors();
    }

    char *secret_hex = BN_bn2hex(BN_bin2bn(secret, secret_size, NULL));
    printf("Shared Secret: %s\n", secret_hex);

    // Cleanup
    OPENSSL_free(pub_key_hex);
    OPENSSL_free(secret_hex);
    BN_free(bob_pub_key);
    free(secret);
    DH_free(dh);
    close(sock);

    return 0;
}

