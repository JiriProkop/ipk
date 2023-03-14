#include <stdio.h>
#ifndef __linux__
fprintf(stderr, "Requires linux OS!!\n");
exit(-1);
// Socket binding works differently on Windows.
#endif

#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFSIZE 1024
#define UDP_READBUF_SIZE 10
#define UDP_MSG_SIZE 12

/*
    @enum opcodes for Calculator UDP protocol
*/
enum opcodes {
    op_request,
    op_response,
};

/*
   @enum status codes for Calculator UDP protocol
*/
enum stat_codes {
    stat_ok,
    stat_error,
};

bool toclose = false;
int client_socket;

/*
    Interrupt signal handlerer.
*/
static void sig_handler(int _) {
    (void)_;
    if (toclose) {
        send(client_socket, "BYE\n", strlen("BYE\n"), 0);
        close(client_socket);
    }
    exit(EXIT_SUCCESS);
}

/*
    Communicate with server by tcp.

    @param server_address server address where the server is.
*/
void tcp_com(struct sockaddr_in server_address) {
    int bytestx, bytesrx;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        perror("ERR: socket\n");
        exit(EXIT_FAILURE);
    }
    if (connect(client_socket, (const struct sockaddr *)&server_address, sizeof(server_address)) != 0) {
        perror("ERR: connect");
        exit(EXIT_FAILURE);
    }
    toclose = true;
    char buf[BUFSIZE] = {0};
    // send each problem(=line) to server and print answer
    while (fgets(buf, BUFSIZE, stdin) != NULL) {
        bytestx = send(client_socket, buf, strlen(buf), 0);
        if (bytestx < 0) {
            perror("ERR: in sendto\n");
            close(client_socket);
            exit(EXIT_FAILURE);
        }
        std::fill_n(buf, BUFSIZE, 0);
        bytesrx = recv(client_socket, buf, BUFSIZE, 0);
        if (bytesrx < 0) {
            close(client_socket);
            perror("ERR: in recvfrom\n");
            exit(EXIT_FAILURE);
        }
        printf("%s", buf);
        std::fill_n(buf, BUFSIZE, 0);
    } // end of while
    close(client_socket);
}

/*
    Communicate with server by udp.

    @param server_address server address where the server is.
*/
void udp_com(struct sockaddr_in server_address) {
    int bytestx, bytesrx;
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) <= 0) {
        perror("ERR: socket\n");
        exit(EXIT_FAILURE);
    }
    socklen_t serverlen = sizeof(server_address);
    char readbuf[UDP_READBUF_SIZE] = {0};
    char solve[UDP_MSG_SIZE] = {0};
    // send each problem(=line) to server and print answer
    while (fgets(readbuf, UDP_READBUF_SIZE, stdin) != NULL) {
        sprintf(solve, "%c%c%s", op_request, (int)strlen(readbuf), readbuf);

        bytestx = sendto(client_socket, solve, UDP_MSG_SIZE, 0, (struct sockaddr *)&server_address, serverlen);
        if (bytestx < 0) {
            perror("ERR: sendto\n");
            exit(EXIT_FAILURE);
        }
        std::fill_n(solve, UDP_MSG_SIZE, 0);

        bytesrx = recvfrom(client_socket, solve, UDP_MSG_SIZE, 0, (struct sockaddr *)&server_address, &serverlen);
        if (bytesrx < 0) {
            perror("ERR: recvfrom\n");
            exit(EXIT_FAILURE);
        }
        if (solve[1] == stat_error) {
            fprintf(stderr, "ERR:%s\n", solve + 3); // skipping the first 3 flag chars
        } else {
            printf("OK:%s\n", solve + 3);
        }
        std::fill_n(readbuf, UDP_READBUF_SIZE, 0);
        std::fill_n(solve, UDP_MSG_SIZE, 0);
    }
}

int main(int argc, const char *argv[]) {
    int port_number;
    const char *server_hostname;
    struct hostent *server;
    struct sockaddr_in server_address;
    signal(SIGINT, sig_handler);
    // param validation
    if (argc != 7 || strcmp("-h", argv[1]) != 0 || strcmp("-p", argv[3]) != 0 || strcmp("-m", argv[5]) != 0 ||
        (strcmp(argv[6], "udp") != 0 && strcmp(argv[6], "tcp") != 0)) {
        fprintf(stderr, "usage:\t%s -h <host> -p <port> -m <mode>\n", argv[0]);
        fprintf(stderr, "<mode>:\t'tcp' or 'udp'\n");
        exit(EXIT_FAILURE);
    }
    server_hostname = argv[2];
    port_number = atoi(argv[4]);
    if(!(port_number > 0 && port_number <= 65535)) { // unsgined 16 bit range
        fprintf(stderr, "Port number has to be within bounds of 16bit unsigned integer!\n");
        exit(EXIT_FAILURE);
    } else if(port_number <= 1023) {
        fprintf(stderr, "This port number is reserved(0 - 1023)!\n");
        exit(EXIT_FAILURE);
    }
    // getting host by dns
    if ((server = gethostbyname(server_hostname)) == NULL) {
        fprintf(stderr, "ERROR: no such host as %s\n", server_hostname);
        exit(EXIT_FAILURE);
    }

    // getting server IP address
    bzero((char *)&server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(port_number);

    if (argv[6][0] == 't') {
        tcp_com(server_address);
    } else {
        udp_com(server_address);
    }

    return 0;
}
