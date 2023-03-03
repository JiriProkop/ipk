#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFSIZE 1024

int main(int argc, const char *argv[]) {
    int client_socket, port_number, bytestx, bytesrx;
    const char *server_hostname;
    struct hostent *server;
    struct sockaddr_in server_address;
    socklen_t serverlen;

    // test vstupnich parametru:
    if (argc != 7 || strcmp("-h", argv[1]) != 0 || strcmp("-p", argv[3]) != 0 || strcmp("-m", argv[5]) != 0 ||
        (strcmp(argv[6], "udp") != 0 && strcmp(argv[6], "tcp") != 0)) {
        fprintf(stderr, "usage:\t%s -h <host> -p <port> -m <mode>\n", argv[0]);
        fprintf(stderr, "<mode>:\t'tcp' or 'udp'\n");
        exit(EXIT_FAILURE);
    }
    server_hostname = argv[2];
    port_number = atoi(argv[4]);

    /* 2. ziskani adresy serveru pomoci DNS */
    if ((server = gethostbyname(server_hostname)) == NULL) {
        fprintf(stderr, "ERROR: no such host as %s\n", server_hostname);
        exit(EXIT_FAILURE);
    }

    /* 3. nalezeni IP adresy serveru a inicializace struktury server_address */
    bzero((char *)&server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number);

    /* Vytvoreni soketu */
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (const struct sockaddr *)&server_address, sizeof(server_address)) != 0) {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }

    // Komunikace.

    char buf[BUFSIZE] = {0};

    while (fgets(buf, BUFSIZE, stdin) != NULL) { // nacteni zprav od uzivatele
        bytestx = send(client_socket, buf, strlen(buf), 0);
        if (bytestx < 0) {
            perror("ERROR in sendto");
            exit(EXIT_FAILURE);
        }
        std::fill_n(buf, BUFSIZE, 0);
        bytesrx = recv(client_socket, buf, BUFSIZE, 0);
        if (bytesrx < 0) {
            perror("ERROR in recvfrom");
        }
        printf("%s", buf);
        std::fill_n(buf, BUFSIZE, 0);
    } // end of while

    close(client_socket);
    return 0;
}
