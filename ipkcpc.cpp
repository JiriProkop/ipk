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
#define UDP_READBUF_SIZE 10
#define UDP_MSG_SIZE 12

enum opcodes {
    op_request,
    op_response,
};

enum stat_codes {
    stat_ok,
    stat_error,
};

void tcp_com(struct sockaddr_in server_address) {
    int client_socket, bytestx, bytesrx;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    if (connect(client_socket, (const struct sockaddr *)&server_address, sizeof(server_address)) != 0) {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }
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
}

void udp_com(struct sockaddr_in server_address) {
    int client_socket, bytestx, bytesrx;
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    socklen_t serverlen = sizeof(server_address);
    char readbuf[UDP_READBUF_SIZE] = {0};
    char solve[UDP_MSG_SIZE] = {0};

    while (fgets(readbuf, UDP_READBUF_SIZE, stdin) != NULL) {
        sprintf(solve, "%c%c%s", op_request, (int)strlen(readbuf), readbuf);
        printf("Msg in ascii: ");
        for (size_t i = 0; i < strlen(readbuf) + 2; i++) {
            printf("%d ", solve[i]);
        }
        printf("\n");
        /* odeslani zpravy na server */
        bytestx = sendto(client_socket, solve, UDP_MSG_SIZE, 0, (struct sockaddr *)&server_address, serverlen);
        if (bytestx < 0) {
            perror("ERROR: sendto");
            exit(EXIT_FAILURE);
        }
        printf("msg send\n");
        std::fill_n(solve, UDP_MSG_SIZE, 0);
        /* prijeti odpovedi a jeji vypsani */
        bytesrx = recvfrom(client_socket, solve, UDP_MSG_SIZE, 0, (struct sockaddr *)&server_address, &serverlen);
        printf("msg received\n");
        if (bytesrx < 0) {
            perror("ERROR: recvfrom");
            exit(EXIT_FAILURE);
        }
        // removing codes from msg
        solve[0] = (char)1;
        solve[1] = (char)1;
        solve[2] = (char)1;

        printf("Echo from server:%s", solve);
        std::fill_n(readbuf, UDP_READBUF_SIZE, 0);
        std::fill_n(solve, UDP_MSG_SIZE, 0);
    }

}

int main(int argc, const char *argv[]) {
    int port_number;
    const char *server_hostname;
    struct hostent *server;
    struct sockaddr_in server_address;

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

    if (argv[6][0] == 't') {
        tcp_com(server_address);
    } else {
        printf("udp mode\n");
        udp_com(server_address);
    }

    return 0;
}
