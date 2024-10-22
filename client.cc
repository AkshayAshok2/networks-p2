/*///////////////////////////////////////////////////////////
*
* FILE:		client.cc
* AUTHORS:	Akshay Ashok and Joshua Thomas
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Client Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unordered_map>
#include <vector>

/* Constants */
#define RCVBUFSIZE 512		    /* The receive buffer size */
#define SNDBUFSIZE 512		    /* The send buffer size */
#define MDLEN 32
#define DATA_DIR "client_files"

void fatal_error(const std::string& msg) {
    perror(msg.c_str());
    exit(1);
}

typedef struct {
    int messageType;
    char type;
    char *content;
} message;

/* The main function */
int main(int argc, char *argv[]) {
    int clientSock;		    /* socket descriptor */
    int msgLen;
    struct sockaddr_in serv_addr;   /* The server address */
    struct sockaddr_in client_addr; /* The client address */

    char *listedFiles;

    char sndBuf[EVP_MAX_MD_SIZE];	    /* Send Buffer */
    char rcvBuf[EVP_MAX_MD_SIZE];	    /* Receive Buffer */

    int servPort = 10000;
    char *servIP = "127.0.0.1";
    
    /*
    memset(&sndBuf, 0, RCVBUFSIZE);
    memset(&rcvBuf, 0, RCVBUFSIZE);

    msgLen = 0;
    strncpy(sndBuf, studentName, msgLen);
    sndBuf[msgLen] = '\0';
    */

    /* Create a new TCP socket*/
    if ((clientSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        fatal_error("socket() failed");

    /* Construct the server address structure */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family        = AF_INET;
    serv_addr.sin_port          = htons(servPort);
    serv_addr.sin_addr.s_addr   = inet_addr(servIP);

    /* Establish connection to the server */
    if (connect(clientSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        fatal_error("connect() failed");

    printf("Welcome to UFmyMusic!\n");
    
    while (1) {
        printf("Select an option:\n1. LIST\n2. DIFF\n3. PULL\n4. LEAVE\n");

        int option;
        scanf("%d", &option);

        switch (option) {
            case 1:
                // Send the integer 1 to the server
                if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
                    fatal_error("send() sent unexpected number of bytes");

                // Receive the raw data into the receive buffer
                int receivedBytes = recv(clientSock, rcvBuf, RCVBUFSIZE, 0);

                if (receivedBytes < 0)
                    fatal_error("recv() failed");
                else if (receivedBytes == 0)
                    printf("Connection closed by server.\n");
                else {
                    // Deserialize the message struct from the receive buffer
                    message msg;
                    memcpy(&msg.messageType, rcvBuf, sizeof(int));
                    memcpy(&msg.type, rcvBuf + sizeof(int), sizeof(char));

                    // Deserialize the content field
                    int contentLength = receivedBytes - sizeof(int) - sizeof(char);
                    msg.content = malloc(contentLength + 1); // +1 for null terminator
                    if (msg.content == NULL)
                        fatal_error("malloc() failed");

                    // Copy the content from the receive buffer
                    memcpy(msg.content, rcvBuf + sizeof(int) + sizeof(char), contentLength);
                    msg.content[contentLength] = '\0'; // Null-terminate the string

                    printf("Received message:\n");
                    printf("Message Type: %d\n", msg.messageType);
                    printf("Type: %c\n", msg.type);
                    printf("Content: %s\n", msg.content);

                    // Free the allocated memory for content
                    free(msg.content);
                }
                break;

            case 2:
                strcpy(sndBuf, "DIFF");
                msgLen = strlen(sndBuf);
                break;
            case 3:
                strcpy(sndBuf, "PULL");
                msgLen = strlen(sndBuf);
                break;
            case 4:
                strcpy(sndBuf, "LEAVE");
                msgLen = strlen(sndBuf);
                break;
            default:
                printf("Invalid option. Please try again.\n");
                continue;
        }
        /*
        // Send the string to the server
        if (send(clientSock, sndBuf, msgLen, 0) != msgLen)
            fatal_error("send() sent unexpected number of bytes");

        // Receive and print response from the server
        int receivedBytes = 1;
        while (receivedBytes > 0) {
            if ((receivedBytes = recv(clientSock, rcvBuf, RCVBUFSIZE - 1, 0)) < 0) {
                fatal_error("recv() failed");
            }
        }
        */
    }

    close(clientSock);
    return 0;
}

