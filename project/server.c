#include "consts.h"
#include "security.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/fcntl.h>
#define MAXBUF 2048



//The program expects at least one argument: the TCP port on which to listen
//If you don't supply a port, it prints a usage message and exits wtiih zero
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: server <port>\n");
        exit(1);
    }

    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // use IPv4  use UDP
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    /* Construct our address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    server_addr.sin_addr.s_addr =
        INADDR_ANY; // accept all connections
                    // same as inet_addr("0.0.0.0")
                    // "Address string to network bytes"
    // Set receiving port
    int PORT = atoi(argv[1]);
    server_addr.sin_port = htons(PORT); // Big endian

   

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(1);
    }

    // Listen for new clients
    // listen()
    if (listen(sockfd, 10) < 0) {
        perror("listen");
        close(sockfd);
        exit(1);
    }
    

    struct sockaddr_in client_addr; // Same information, but about client
    socklen_t client_size = sizeof(client_addr);
    //Here we are accepting a single client
    int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_size);
    if (clientfd < 0) {
        perror("accept");
        close(sockfd);
        exit(1);
    }

    // Accept client connection
    // clientfd = accept()

    //Make client socket nonblocking
    int flags = fcntl(clientfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(clientfd, F_SETFL, flags);
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(clientfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));

    init_sec(SERVER_CLIENT_HELLO_AWAIT, NULL, argc > 2);

    uint8_t in_buf[MAXBUF], out_buf[MAXBUF];
    ssize_t rlen, slen;

    // 7) Main loop: handshake then data
    while (1) {
        // A) Try to receive from client
        rlen = recv(clientfd, in_buf, sizeof(in_buf), 0);
        if (rlen > 0) {
            output_sec(in_buf, (size_t)rlen);
        }

        // B) Ask FSM if there's a message to send
        slen = input_sec(out_buf, sizeof(out_buf));
        if (slen > 0) {
            send(clientfd, out_buf, (size_t)slen, 0);
        }

        // C) Optionally detect closure
        if (rlen == 0) break;
        if (rlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) break;

        // Small sleep to avoid busy spin
        usleep(10000);
    }

    close(clientfd);
    close(sockfd);
    return 0;
}
