#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#define EVE_PORT 9090
#define BOB_PORT 8080

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

DH *load_dh_params() {
    DH *dh = NULL;
    FILE *param_file = fopen("dhparams.pem", "r");

    if (!param_file) {
        perror("Unable to open file with DH parameters");
        exit(EXIT_FAILURE);
    }

    dh = PEM_read_DHparams(param_file, NULL, NULL, NULL);
    fclose(param_file);

    if (!dh) {
        fprintf(stderr, "Error reading DH parameters from file\n");
        handleErrors();
    }

    if (1 != DH_generate_key(dh)) {
        handleErrors();
    }

    return dh;
}

void compute_and_print_shared_secret(DH *dh, const char *peer_pub_key_hex) {
    BIGNUM *peer_pub_key = NULL;
    BIGNUM *secret_bn = NULL;
    BN_hex2bn(&peer_pub_key, peer_pub_key_hex);
    unsigned char *secret = (unsigned char *)malloc(DH_size(dh));

    if (!secret) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // **************************************
    // 1.3 Compute Eve shared secret
    // **************************************

    int secret_size = DH_compute_key(secret, peer_pub_key, dh);
    if (secret_size == -1) {
        // Error handling
        fprintf(stderr, "Failed to compute the shared secret\n");
        exit(EXIT_FAILURE);
    }
    
    //***************************************


	
    // **************************************
    // 1.3 Display the shared secret obtained
    // **************************************
     printf("Shared Secret: ");
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
    
    //***************************************

    BN_free(peer_pub_key);
    BN_free(secret_bn);
    free(secret);
}


int main() {

    int alice_fd, bob_fd, alice_client_socket;
    struct sockaddr_in alice_address, bob_address;
    int alice_addrlen = sizeof(alice_address);
    
    char buffer[2048];
    
    // Load Eve's dh key pair
    DH *eve_dh = load_dh_params();
    
    const BIGNUM *eve_pub_key;
    // **************************************
    // 1.3 Extract the Eve's public key 
    // **************************************
   
   DH_get0_key(eve_dh, &eve_pub_key, NULL); // Extracts the public key part of eve_dh
    char *eve_pub_key_hex = BN_bn2hex(eve_pub_key);




    //***************************************


    // Eve-to-Alice connection
    if ((alice_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    alice_address.sin_family = AF_INET;
    alice_address.sin_addr.s_addr = INADDR_ANY;
    alice_address.sin_port = htons(EVE_PORT);

    if (bind(alice_fd, (struct sockaddr *)&alice_address, sizeof(alice_address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(alice_fd, 10) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }

    printf("Eve is waiting for Alice's connections...\n\n");
    
    
    // Waiting Alice to send messages
    if ((alice_client_socket = accept(alice_fd, (struct sockaddr *)&alice_address, (socklen_t*)&alice_addrlen)) < 0) {
        perror("Accept");
        exit(EXIT_FAILURE);
    }

    // read alice pub key
    // **************************************
    // 1.3 Read the public key sent by Alice
    // **************************************
    read(alice_client_socket, buffer, 2048);

    //***************************************
    
    printf("Eve intercepted Alice's public key: %s\n\n", buffer);
    
     BIGNUM *alice_pub_key_bn = NULL;
    BN_hex2bn(&alice_pub_key_bn, buffer);
    
    printf("Eve computing shared secret with Alice...\n\n");
    // **************************************
    // 1.3 Compute Eve-Alice's shared secret
    // **************************************
 // Compute Eve-Alice's shared secret
    unsigned char *alice_secret = (unsigned char *)malloc(DH_size(eve_dh));
    int secret_size_alice = DH_compute_key(alice_secret, alice_pub_key_bn, eve_dh);

    // For simplicity, not displaying the shared secret...
    if (secret_size_alice == -1) {
        // Error handling
        fprintf(stderr, "Failed to compute the shared secret\n");
        exit(EXIT_FAILURE);
    }
    
    //***************************************


	
    // **************************************
    // 1.3 Display the shared secret obtained
    // **************************************
     printf("Shared Secret: ");
    for (int i = 0; i < secret_size_alice; i++) {
        printf("%02x", alice_secret[i]);
    }
    printf("\n");

    //***************************************

    
    // **************************************
    // 1.3 Send Eve's public key to Alice
    // **************************************
    
    write(alice_client_socket, eve_pub_key_hex, strlen(eve_pub_key_hex) + 1);


    //***************************************
    
    // Eve-to-Bob connection
    if ((bob_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    bob_address.sin_family = AF_INET;
    bob_address.sin_port = htons(BOB_PORT);

	
    if(inet_pton(AF_INET, "127.0.0.1", &bob_address.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        return -1;
    }

    if (connect(bob_fd, (struct sockaddr *)&bob_address, sizeof(bob_address)) < 0) {
        perror("Connection Failed to Bob");
        return -1;
    }


    // **************************************
    // 1.3 Send Eve's public key to Bob
    // **************************************

	 write(bob_fd, eve_pub_key_hex, strlen(eve_pub_key_hex) + 1);


    //***************************************



    // Eve receives Bob's key and displays it
    read(bob_fd, buffer, 2048);  
    printf("Eve intercepted Bob's public key: %s\n\n", buffer);
    
    
    printf("Eve computing shared secret with Bob...\n\n");
    // **************************************
    // 1.3 Compute Eve-Alice's shared secret
    // **************************************

   BIGNUM *bob_pub_key_bn = NULL;
    BN_hex2bn(&bob_pub_key_bn, buffer);

    // Compute Eve-Bob's shared secret
    unsigned char *bob_secret = (unsigned char *)malloc(DH_size(eve_dh));
    int secret_size_bob = DH_compute_key(bob_secret, bob_pub_key_bn, eve_dh);
   
    if (secret_size_bob == -1) {
        // Error handling
        fprintf(stderr, "Failed to compute the shared secret\n");
        exit(EXIT_FAILURE);
    }
    
    //***************************************


	
    // **************************************
    // 1.3 Display the shared secret obtained
    // **************************************
     printf("Shared Secret: ");
    for (int i = 0; i < secret_size_bob; i++) {
        printf("%02x", bob_secret[i]);
    }
    printf("\n");

    //***************************************

    OPENSSL_free(eve_pub_key_hex);
    BN_free(alice_pub_key_bn);
    BN_free(bob_pub_key_bn);
    free(alice_secret);
    free(bob_secret);
    DH_free(eve_dh);
    close(alice_client_socket);
    close(bob_fd);

    //cleanup
    // OPENSSL_free(eve_pub_key_hex);
    // DH_free(eve_dh);
    // close(alice_client_socket);
    // close(bob_fd);

    return 0;
}
