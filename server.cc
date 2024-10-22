/*///////////////////////////////////////////////////////////
*
* FILE:		server.c
* AUTHORS:	Akshay Ashok and Joshua Thomas
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Server Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */

#include <stdio.h>	  /* for printf() and fprintf() */
#include <sys/socket.h>	  /* for socket(), connect(), send(), and recv() */
#include <arpa/inet.h>	  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>	  /* supports all sorts of functionality */
#include <unistd.h>	  /* for close() */
#include <string.h>	  /* support any string ops */
#include <openssl/evp.h>  /* for OpenSSL EVP digest libraries/SHA256 */

#define RCVBUFSIZE 512		/* The receive buffer size */
#define SNDBUFSIZE 512		/* The send buffer size */
#define BUFSIZE 40		/* Your name can be as many as 40 chars*/
#define DATA_DIR "server_files"

void fatal_error(char *message)
{
    perror(message);
    exit(1);
}

/* The main function */
int main(int argc, char *argv[])
{
  int serverSock;				    /* Server Socket */
  int clientSock;				/* Client Socket */
  struct sockaddr_in changeServAddr;		/* Local address */
  struct sockaddr_in changeClntAddr;		/* Client address */
  unsigned short changeClientPort;    /* Client port */
  unsigned short changeServPort;		/* Server port */
  unsigned int clntLen;			/* Length of address data struct */

  char nameBuf[BUFSIZE];			/* Buff to store name from client */
  unsigned char md_value[EVP_MAX_MD_SIZE];	/* Buff to store change result */
  EVP_MD_CTX *mdctx;				/* Digest data structure declaration */
  const EVP_MD *md;				/* Digest data structure declaration */
  unsigned int md_len;				/* Digest data structure size tracking */

  changeServPort = 10000;

  /* Create new TCP Socket for incoming requests*/
  if ((serverSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    fatal_error("socket() failed");

  /* Construct local address structure*/
  memset(&changeServAddr, 0, sizeof(changeServAddr));
  changeServAddr.sin_family       = AF_INET;
  changeServAddr.sin_addr.s_addr  = htonl(INADDR_ANY);
  changeServAddr.sin_port         = htons(changeServPort);
  
  /* Bind to local address structure */
  if (bind(serverSock, (struct sockaddr *) &changeServAddr, sizeof(changeServAddr)) < 0)
    fatal_error("bind() failed");

  /* Listen for incoming connections */
  if (listen(serverSock, 5) < 0)
    fatal_error("listen() failed");

  /* Loop server forever*/
  while(1)
  {
    /* Accept incoming connection */
    clntLen = sizeof(changeClntAddr);
    if ((clientSock = accept(serverSock, (struct sockaddr *) &changeClntAddr, &clntLen)) < 0)
      fatal_error("accept() failed");

    /* Extract Your Name from the packet, store in nameBuf */
    int bytesReceived;
    if ((bytesReceived = recv(clientSock, nameBuf, RCVBUFSIZE, 0)) < 0)
      fatal_error("recv() failed");

    /* Run this and return the final value in md_value to client */
    /* Takes the client name and changes it */
    /* Students should NOT touch this code */
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, nameBuf, strlen(nameBuf));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    /* Return md_value to client */
    if (send(clientSock, md_value, sizeof(md_value), 0) < 0)
      fatal_error("send() failed");

    close(clientSock);
  }

  close(serverSock);
  return 0;
}

