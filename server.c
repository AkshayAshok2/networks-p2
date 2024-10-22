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

#include <dirent.h> /**/
#include <sys/stat.h>

#include <dirent.h> /**/
#include <sys/stat.h>

#define RCVBUFSIZE 512		/* The receive buffer size */
#define SNDBUFSIZE 512		/* The send buffer size */
#define BUFSIZE 40		/* Your name can be as many as 40 chars*/
#define DATA_DIR "server_files"

#define FILE_READ_BUFSIZE 1024

typedef struct {
  char* fileName;
  char* sha256Hash;
} FileInfo;

typedef struct {
  uint8_t fileNameBytes;
  char fileName[RCVBUFSIZE];
  uint8_t fileHashBytes;
  char fileHash[RCVBUFSIZE];
} listMessageResponse;

#define FILE_READ_BUFSIZE 1024

typedef struct {
  char* fileName;
  char* sha256Hash;
} FileInfo;

typedef struct {
  uint8_t fileNameBytes;
  char fileName[RCVBUFSIZE];
  uint8_t fileHashBytes;
  char fileHash[RCVBUFSIZE];
} listMessageResponse;

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
  int md_len;					/* Digest data structure size tracking */

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
	  mdctx = EVP_MD_CTX_create();
	  EVP_DigestInit_ex(mdctx, md, NULL);
	  EVP_DigestUpdate(mdctx, nameBuf, strlen(nameBuf));
	  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	  EVP_MD_CTX_destroy(mdctx);

    /* Return md_value to client */
    if (send(clientSock, md_value, sizeof(md_value), 0) < 0)
      fatal_error("send() failed");

    close(clientSock);
  }

  close(serverSock);
  return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------

//Function for calculating SHA-256 hash
char* calculateSHA256(const char* filePath){
  
  //open file in binary mode
  FILE* file = fopen(filePath, "rb");
  if(!file){
    perror("fopen");
    return NULL;
  }

  //Initialize EVP context for SHA256
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if(mdctx == NULL){
    perror("EVP_MD_CTX_new");
    fclose(file);
    return NULL;
  }

  //Initialize SHA256 algorithm
  if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1){
    perror("EVP_DigestInit_ex");
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return NULL;
  }

  //Read the file in chunks and update the hash calculation
  unsigned char buffer[FILE_READ_BUFSIZE];
  size_t bytesRead;
  while((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0){
    if(EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1){
      perror("EVP_DigestUpdate");
      EVP_MD_CTX_free(mdctx);
      fclose(file);
      return NULL;
    }
  }

  //Finalize Hash Calculation
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLength;
  if(EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1){
    perror("EVP_DigestFinal_ex");
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return NULL;
  }

  //Convert hash to hexadecimal
  char* hashString = malloc(hashLength * 2 + 1);
  if(hashString == NULL){
    perror("malloc");
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return NULL;
  }
  for(unsigned int i = 0; i < hashLength; i++){
    sprintf(hashString + (i * 2), "%02x", hash[i]);
  }
  hashString[hashLength * 2] = '\0';

  EVP_MD_CTX_free(mdctx);
  fclose(file);

  return hashString;


}

//Function to get file names
listMessageResponse* getFileNames(const char* dirPath) {
  DIR *currentDir;
  struct dirent *entry;
  int fileCount = 0;
  char filePath[1024];
  int capacity = 10; //initial capacity for storing file info

  // Allocate memory for storing file info
  listMessageResponse* fileInfos = malloc(capacity * sizeof(listMessageResponse));
  if(fileInfos == NULL){
    perror("malloc");
    return NULL;
  }

  if((currentDir = opendir(dirPath)) == NULL){
    perror("opendir() error");
    free(fileInfos);
    return NULL;
  }

  int offset = 0;
  // Loop through each entry in the directory
  while ((entry = readdir(currentDir)) != NULL){

    snprintf(filePath, sizeof(filePath), "%s%s", dirPath, entry->d_name);
    struct stat fileStat;
    if (stat(filePath, &fileStat) == 0 && S_ISREG(fileStat.st_mode)){
      //double size if capacity is reached
      if (fileCount >= capacity){
        capacity *= 2;
        listMessageResponse* temp = realloc(fileInfos, capacity * sizeof(listMessageResponse));
        if(temp == NULL){
          perror("realloc");
          closedir(currentDir);
          for(int i = 0; i < fileCount; i++){
            free(fileInfos[i].fileName);
            free(fileInfos[i].fileHash);
          }
          free(fileInfos);
          return NULL;
        }
        fileInfos = temp;
      }

      uint8_t fileNameBytes = strlen(entry->d_name);
      char* sha256 = calculateSHA256(filePath);
      uint8_t fileHashBytes = strlen(sha256);

      memcpy(&fileNameBytes, fileInfos + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t);
      memcpy(&entry->d_name, fileInfos + offset, fileNameBytes);
      offset += RCVBUFSIZE - fileNameBytes;
      memcpy(&fileHashBytes, fileInfos + offset, sizeof(uint8_t));
      offset += sizeof(uint8_t);
      memcpy(sha256, fileInfos + offset, fileHashBytes);
      offset += RCVBUFSIZE - fileHashBytes;

      //fileInfos[fileCount].fileHash = calculateSHA256(filePath); // Store file name and its SHA-256 hash
      if(fileInfos[fileCount].fileHash == NULL){
        printf("Failed to calculate SHA256 for file: %s\n", entry->d_name);
      }

      fileCount++;
    }
  }

  closedir(currentDir);
  return fileInfos; //return array of FileInfo

}

/*int list(){
  printf("Sending Current List of Files to Client\n");


}*/

