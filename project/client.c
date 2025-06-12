#include "consts.h" //Project-specific constants (e.g. message type codes)
#include "security.h" //libsecurity helper APIs (handshake, encrypt/decrypt, etc)
#include <arpa/inet.h> //Definitions for internet operations (inet_addr, htons, etc.)
#include <netdb.h> //DNS lookup (gethostbyname)
#include <stdio.h> //Standard I/O (printf, fprintf)
#include <stdlib.h> //Standard library (exit, malloc, atoi)
#include <string.h> //String manipulation (strcpy, memset)
#include <sys/socket.h> //Socket APIs (socket, setsockopt, connect)
#include <unistd.h> //UNIX standard (close)
#include <sys/fcntl.h> //File control (fcntl for noblocking)
#include <errno.h> //Error codes (errno)


/* 
 * Resolve a hostname (e.g. "example.com") into its IPv4 string (e.g. "93.184.216.34").
 * On failure, prints an error and exits.
 * */
void hostname_to_ip(const char* hostname, char* ip) {
    struct hostent* he;
    struct in_addr** addr_list;

    //Perform DNS lookup for the hostname
    if ((he = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "Error: Invalid hostname\n"); //Print error if lookup fails
        exit(255); //Exit with code 255 indicated DNS error
    }

    //Cast the returned adfdress list to in_addr pointers
    addr_list = (struct in_addr**) he->h_addr_list;

    //Iterate through the returned list of IPs
    for (int i = 0; addr_list[i] != NULL; i++) {
        /*
        Convert the first binary IP address to dotted-decimal string
        inet_ntoa() returns a pointer to a static buffer containing the string
        */
        strcpy(ip, inet_ntoa(*addr_list[i]));
        return;
    }
    //If no addresses found, treat it as an error
    fprintf(stderr, "Error: Invalid hostname\n");
    exit(255);
}

int main(int argc, char** argv) {
    //Verify the correct number of command-line arguments: program, hostname, port
    if (argc < 3) {
        fprintf(stderr, "Usage: client <hostname> <port> \n");
        exit(1);    //Exit with code 1 indicating invalid usage
    }

    /*
    1) Create a TCP socket for IPv4 connections:
        AF_INET = IPv4, SOCK_STREAM = TCP
    */
    /* Create sockets */
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket"); // Print system error on failure
        exit(1);            // Exit indicating socket creation failure
    }
    // use IPv4  use UDP



    /*
    2) Prepare the server address structure for connect():
    */
    /* Construct server address */
    struct sockaddr_in server_addr; //Decalre a struct to hold IPv4 + port
    server_addr.sin_family = AF_INET; // use IPv4, Specify IPv4 address family

    //Buffer to hold the resolved dotted-decimal string
    char addr[100] = {0}; 
    hostname_to_ip(argv[1], addr); //Resolve hostname to IP, store in addr

    //Convert dotted-decimal IP string to binary network-order IP
    server_addr.sin_addr.s_addr = inet_addr(addr);

    //Parse port argument and convert to network byte order
    int PORT = atoi(argv[2]);   //Convert string argument to integer port
    server_addr.sin_port = htons(PORT); // Big endian Convert port to big endian for networ










    //NEED TO WORK ON DUDE!

    /*
     * 3) Initialize security context for client-side handshake:
     *    CLIENT_CLIENT_HELLO_SEND = initial handshake state
     *    argv[1] = expected DNS name for server certificate validation
     *    argc > 3 enables verbose/debug mode in libsecurity
     */
    

    //1. Initiliaze 
    init_sec(CLIENT_CLIENT_HELLO_SEND, argv[1], argc > 3);
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
         perror("connect"); // Print error reason
         exit(1);             // Exit indicating connect failure
    }



    /*
     * 5) Set socket to non-blocking mode so I/O calls won't block:
     */
    // Set the socket nonblocking
    int flags = fcntl(sockfd, F_GETFL); //Get current file status flags
    flags |= O_NONBLOCK; //Add non-blocking flag
    fcntl(sockfd, F_SETFL, flags);
    /*
     * 6) Enable socket options to reuse address and port quickly:
     *    Useful during development to avoid "address already in use" errors
     */
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int));





    /*
     * 7) Main event loop:
     *    - Receive encrypted data from socket, decrypt via security_recv(),
     *      then feed into your reliability_input().
     *    - When your reliability layer has data, call reliability_output()
     *      to get plaintext, then encrypt/send via security_send().
     *    Use select()/poll() or non-blocking checks to multiplex.
     */





// On first iteration, input_sec() in state CLIENT_CLIENT_HELLO_SEND builds
//  + serializes your ClientHello TLV and you send() it.

// On subsequent loops, input_sec() returns 0 until you receive the ServerHello, 
// at which point output_sec() parses it, verifies the cert/signature, derives keys, and transitions you to the next state.

// Eventually you send a Finished TLV and then fall into DATA_STATE. 
// From that point on, each input_sec() call will pull raw bytes from input_io(), encrypt & MAC them, and return a DATA TLV for you to 
// send(). Likewise, each output_sec() call will decrypt + verify incoming DATA TLVs and hand you plaintext via output_io().

    uint8_t in_buf[2048], out_buf[2048];   
    ssize_t to_send, recvd;

    while(1) {
        //1) Outbound: get the next handhsake or data record
        to_send = input_sec(out_buf, sizeof out_buf);
        if (to_send > 0){
            send(sockfd, out_buf, to_send, 0);
        }

        //2. Inbound: pull in whatever the server just sent
        recvd = recv(sockfd, in_buf, sizeof in_buf, 0);
        if (recvd > 0){
            output_sec(in_buf, recvd);
        }

        // 3) (break out to avoid spinning perhaps?)


        //TODOOOOOOOOOOOO
        // receive data
        // send data
    }
    close(sockfd);
    return 0;
}
