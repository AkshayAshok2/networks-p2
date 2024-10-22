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
#include <openssl/sha.h>
#include <dirent.h> /**/
#include <sys/stat.h>

#define RCVBUFSIZE 512		/* The receive buffer size */
#define SNDBUFSIZE 512		/* The send buffer size */
#define BUFSIZE 40		/* Your name can be as many as 40 chars*/
#define DATA_DIR "server_files"

#define FILE_READ_BUFSIZE 1024


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

listMessageResponse* getFileNamesAndHashes(uint8_t* fileCount);

/* The main function */
int main(int argc, char *argv[])
{
      uint8_t fileCount;
      int serverSock;				    // Server Socket 
      int clientSock;				// Client Socket 
      struct sockaddr_in serv_addr;	// Local address 
      struct sockaddr_in client_addr;		// Client address 
      unsigned short clientPort;    // Client port 
      unsigned short servPort;		// Server port 
      unsigned int clntLen;

      char nameBuf[BUFSIZE];			// Buff to store name from client 
      unsigned char md_value[EVP_MAX_MD_SIZE];	// Buff to store change result 
      EVP_MD_CTX *mdctx;				// Digest data structure declaration 
      const EVP_MD *md;				// Digest data structure declaration 
      int md_len;					// Digest data structure size tracking 

      servPort = 20000;

      // Create new TCP Socket for incoming requests
      if ((serverSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        fatal_error("socket() failed");

      // Construct local address structure
      memset(&serv_addr, 0, sizeof(serv_addr));
      serv_addr.sin_family       = AF_INET;
      serv_addr.sin_addr.s_addr  = htonl(INADDR_ANY);
      serv_addr.sin_port         = htons(servPort);
      
      // Bind to local address structure 
      if (bind(serverSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        fatal_error("bind() failed");

      // Listen for incoming connections 
      if (listen(serverSock, 5) < 0)
        fatal_error("listen() failed");

      while(1){
        // Accept incoming connection 
        clntLen = sizeof(client_addr);
        if ((clientSock = accept(serverSock, (struct sockaddr *) &client_addr, &clntLen)) < 0)
          fatal_error("accept() failed");
        
        int bytesReceived;
        if ((bytesReceived = recv(clientSock, nameBuf, 1, 0)) < 0)
          fatal_error("recv() failed");

        int switchValue = (int)nameBuf[0];
        printf("Received menu choice: %d\n", switchValue);

        switch (switchValue)
        {
          case 1:
            /* ---------- LIST ---------- */
            listMessageResponse* responses = getFileNamesAndHashes(&fileCount);

            int totalSize = sizeof(uint8_t) + fileCount * sizeof(listMessageResponse);
            char *buffer = (char *)malloc(totalSize);
            memset(buffer, 0, totalSize);

            if (buffer == NULL) {
                fatal_error("malloc() failed for buffer");
            }

            // Serialize the data
            int offset = 0;
            memcpy(buffer, &fileCount, sizeof(uint8_t));
            offset += sizeof(uint8_t);

            for (int i = 0; i < fileCount; i++) {
              memcpy(buffer + offset, &responses[i], sizeof(listMessageResponse));
              
              // Verify the copied data
              listMessageResponse* verifyPtr = (listMessageResponse*)(buffer + offset);
              if (memcmp(verifyPtr, &responses[i], sizeof(listMessageResponse)) != 0) {
                fprintf(stderr, "Data verification failed at index %d\n", i);
                free(buffer);
                close(clientSock);
                exit(1);
              } else {
                // Print the relevant section of memory to output
                printf("Memory content at index %d:\n", i);
                for (int j = 0; j < sizeof(listMessageResponse); j++) {
                  printf("%02x ", *((unsigned char*)(buffer + offset + j)));
                }
                printf("\n");
              }

              offset += sizeof(listMessageResponse);
            }

            int totalBytesSent = 0;
            int bytesSent;

            while (totalBytesSent < totalSize) {
                bytesSent = send(clientSock, buffer + totalBytesSent, totalSize - totalBytesSent, 0);

                if (bytesSent < 0) {
                    fatal_error("send() failed");
                }

                totalBytesSent += bytesSent;
            }

            free(buffer);
            break;
          case 3:
            /* ---------- PULL ---------- */
            break;
          case 4:
            /* ---------- LEAVE ---------- */
            break;
          default:
            /* ---------- Invalid option ---------- */
            break;
        }

        if (send(clientSock, md_value, sizeof(md_value), 0) < 0)
          fatal_error("send() failed");

        close(clientSock);

      }

      //const char* dirPath = "./server_files";
      //listMessageResponse* responses = getFileNamesAndHashes(dirPath);
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
listMessageResponse* getFileNamesAndHashes(uint8_t* fileCount) {
    DIR *currentDir;
    struct dirent *entry;
    char filePath[1024];
    int capacity = 10;
    uint8_t currFileCount = 0;

    listMessageResponse* fileInfos = malloc(capacity * sizeof(listMessageResponse));
    if (fileInfos == NULL) {
        perror("malloc");
        return NULL;
    }

    if ((currentDir = opendir(DATA_DIR)) == NULL) {
        perror("opendir() error");
        free(fileInfos);
        return NULL;
    }

    while ((entry = readdir(currentDir)) != NULL) {
        snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, entry->d_name);
        struct stat fileStat;

        if (stat(filePath, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
            // Double size if capacity is reached
            if (currFileCount >= capacity) {
                capacity *= 2;
                listMessageResponse* temp = realloc(fileInfos, capacity * sizeof(listMessageResponse));
                if (temp == NULL) {
                    perror("realloc");
                    closedir(currentDir);
                    free(fileInfos);
                    return NULL;
                }
                fileInfos = temp;
            }

            strncpy(fileInfos[currFileCount].fileName, entry->d_name, RCVBUFSIZE - 1);
            fileInfos[currFileCount].fileName[RCVBUFSIZE - 1] = '\0';
            fileInfos[currFileCount].fileNameBytes = (uint8_t)strlen(entry->d_name);

            // Calculate and copy SHA-256 hash
            char* sha256 = calculateSHA256(filePath);
            if (sha256 != NULL) {
                strncpy(fileInfos[currFileCount].fileHash, sha256, RCVBUFSIZE - 1);
                fileInfos[currFileCount].fileHash[RCVBUFSIZE - 1] = '\0';
                fileInfos[currFileCount].fileHashBytes = (uint8_t)strlen(sha256);
                free(sha256);
            } else {
                fprintf(stderr, "Failed to calculate SHA256 for file: %s\n", entry->d_name);
                continue;
            }

            currFileCount++;
        }
    }

    *fileCount = currFileCount;
    closedir(currentDir);
    return fileInfos;
}

