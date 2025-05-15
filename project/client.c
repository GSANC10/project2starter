#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <errno.h>

void hostname_to_ip(const char* hostname, char* ip) {
    struct hostent* he;
    struct in_addr** addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: Invalid hostname\n");
        exit(255);
    }

    addr_list = (struct in_addr**) he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return;
    }

    fprintf(stderr, "Error: Invalid hostname\n");
    exit(255);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: client <hostname> <port> \n");
        exit(1);
    }

    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // use IPv4  use UDP

    /* Construct server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    char addr[100] = {0};
    hostname_to_ip(argv[1], addr);
    server_addr.sin_addr.s_addr = inet_addr(addr);
    // Set sending port
    int PORT = atoi(argv[2]);
    server_addr.sin_port = htons(PORT); // Big endian

    init_sec(CLIENT_CLIENT_HELLO_SEND, argv[1], argc > 3);
    // Connect to server
    // connect()

    // Set the socket nonblocking
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    while(1) {
        // receive data
        // send data
    }
    close(sockfd);
    return 0;
}
