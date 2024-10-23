/*///////////////////////////////////////////////////////////
*
* FILE:		server.c
* AUTHORS:	Akshay Ashok and Joshua Thomas
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Server Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <pthread.h>

#define RCVBUFSIZE 512		/* The receive buffer size */
#define SNDBUFSIZE 512		/* The send buffer size */
#define BUFSIZE 40		/* Your name can be as many as 40 chars*/
#define DATA_DIR "./server_files"
#define FILE_READ_BUFSIZE 1024
#define SERVER_PORT 59000

/* Struct definitions */
typedef struct {
  uint8_t fileNameBytes;
  char fileName[RCVBUFSIZE];
  uint8_t fileHashBytes;
  char fileHash[RCVBUFSIZE];
} ListMessageResponse;

typedef struct {
    uint8_t fileNameBytes;
    char fileName[RCVBUFSIZE];
    uint32_t fileContentsBytes;
    char *fileContents;
} PullMessageResponse;

typedef struct {
  uint8_t fileNameBytes;
  char fileName[RCVBUFSIZE];
  uint8_t fileHashBytes;
  char fileHash[RCVBUFSIZE];
} DiffMessage;

/* Function prototypes */


ListMessageResponse* getFileNamesAndHashes(uint8_t* fileCount);
void sendSingleFile(int clientSock, const char *fileName, uint8_t fileNameBytes);
char * calculateSHA256(const char * filePath);

/* The main function */
int main(int argc, char *argv[])
{
      uint8_t fileCount;
      int serverSock;
      int clientSock;
      struct sockaddr_in serv_addr;
      struct sockaddr_in client_addr;		// Client address 
      unsigned int clntLen;

      char *rcvBuf;			// Buff to store requested files from client
      EVP_MD_CTX *mdctx;				// Digest data structure declaration
      const EVP_MD *md;				// Digest data structure declaration 
      int md_len;					// Digest data structure size tracking

      ListMessageResponse *serverFiles;

      // Create new TCP Socket for incoming requests
      if ((serverSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        fatal_error("socket() failed");

      // Construct local address structure
      memset(&serv_addr, 0, sizeof(serv_addr));
      serv_addr.sin_family       = AF_INET;
      serv_addr.sin_addr.s_addr  = htonl(INADDR_ANY);
      serv_addr.sin_port         = htons(SERVER_PORT);
      
      // Bind to local address structure 
      if (bind(serverSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        fatal_error("bind() failed");

      // Listen for incoming connections 
      if (listen(serverSock, 5) < 0)
        fatal_error("listen() failed");

      // Outer loop to handle new incoming connections
      while (1) {
        clntLen = sizeof(client_addr);
        if ((clientSock = accept(serverSock, (struct sockaddr *) &client_addr, &clntLen)) < 0)
          fatal_error("accept() failed");

        // Inner loop to process commands on existing connection
        while (1) {
          int bytesReceived;
          uint8_t command;

          if ((bytesReceived = recv(clientSock, &command, 1, 0)) < 0)
            fatal_error("recv() failed");
          else if (bytesReceived == 0)
            fatal_error("Connection closed by client.");

          printf("Received menu choice: %u\n", command);

          if (command == 1) {
            /* ---------- LIST ---------- */
            serverFiles = getFileNamesAndHashes(&fileCount);

            if (serverFiles == NULL)
              fatal_error("getFileNamesAndHashes() failed");

            int totalSize = sizeof(uint8_t) + fileCount * (2 * sizeof(uint8_t) + 2 *RCVBUFSIZE);
            char *buffer = (char *)malloc(totalSize);
            
            if (buffer == NULL) {
              fatal_error("malloc() failed for buffer");
            }

            memset(buffer, 0, totalSize);

            // Serialize the data
            int offset = 0;
            memcpy(buffer, &fileCount, sizeof(uint8_t));
            offset += sizeof(uint8_t);

            for (int i = 0; i < fileCount; i++) {
              memcpy(buffer + offset, &serverFiles[i].fileNameBytes, sizeof(uint8_t));
              offset += sizeof(uint8_t);
              memcpy(buffer + offset, serverFiles[i].fileName, RCVBUFSIZE);
              offset += RCVBUFSIZE;
              memcpy(buffer + offset, &serverFiles[i].fileHashBytes, sizeof(uint8_t));
              offset += sizeof(uint8_t);
              memcpy(buffer + offset, serverFiles[i].fileHash, RCVBUFSIZE);
              offset += RCVBUFSIZE;
            }

            // Send the data
            int totalBytesSent = 0;
            int bytesSent;

            while (totalBytesSent < totalSize) {
                bytesSent = send(clientSock, buffer + totalBytesSent, totalSize - totalBytesSent, 0);

                if (bytesSent < 0) {
                    fatal_error("send() failed");
                }
                else if (bytesSent == 0) {
                    fatal_error("Connection closed by client.\n");
                }

                totalBytesSent += bytesSent;
            }

            free(buffer);
            buffer = NULL;
          } else if (command == 3) {
            /* ---------- PULL ---------- */
            uint8_t diffFileCount;
            int bytesReceived = recv(clientSock, &diffFileCount, sizeof(uint8_t), 0);

            if (bytesReceived < 0)
              fatal_error("Initial recv() failed");
            else if (bytesReceived == 0)
              fatal_error("Connection closed by server for first byte.\n");

            printf("Number of files to pull: %d\n", diffFileCount);

            uint32_t totalMessageSize = diffFileCount * (2 * sizeof(uint8_t) + 2 * RCVBUFSIZE);

            if (rcvBuf != NULL) {
              free(rcvBuf);
              rcvBuf = NULL;
            }

            rcvBuf = (char *)malloc(totalMessageSize);

            if (rcvBuf == NULL)
              fatal_error("malloc() failed for rcvBuf");

            memset(rcvBuf, 0, totalMessageSize);
            int totalBytesReceived = 0;

            // Receive DIFF from client
            while (totalBytesReceived < totalMessageSize) {
              bytesReceived = recv(clientSock, rcvBuf + totalBytesReceived, totalMessageSize - totalBytesReceived, 0);

              if (bytesReceived < 0)
                fatal_error("recv() for file names and hashes failed");
              else if (bytesReceived == 0) {
                printf("Total bytes received: %d\nTotal message size: %d", totalBytesReceived, totalMessageSize);
                fatal_error("Connection closed by client?");
              }

              totalBytesReceived += bytesReceived;
            }

            DiffMessage *diffFiles = (DiffMessage *)malloc(totalMessageSize);

            if (diffFiles == NULL)
              fatal_error("malloc() failed for serverFiles");

            memset(diffFiles, 0, totalMessageSize);
            int offset = 0;

            // Deserialize each listMessageResponse
            for (int i = 0; i < diffFileCount; i++) {
              DiffMessage *diffFile = &diffFiles[i];

              // Deserialize fileNameBytes
              memcpy(&diffFile->fileNameBytes, rcvBuf + offset, sizeof(uint8_t));
              offset += sizeof(uint8_t);

              // Deserialize fileName
              memcpy(diffFile->fileName, rcvBuf + offset, diffFile->fileNameBytes);
              offset += RCVBUFSIZE;

              // Deserialize fileHashBytes
              memcpy(&diffFile->fileHashBytes, rcvBuf + offset, sizeof(uint8_t));
              offset += sizeof(uint8_t);

              // Deserialize fileHash
              memcpy(diffFile->fileHash, rcvBuf + offset, diffFile->fileHashBytes);
              offset += RCVBUFSIZE;
            }

            free(rcvBuf);
            rcvBuf = NULL;

            // Send number of files being sent to client
            if (send(clientSock, &diffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t))
              fatal_error("send() for diffFileCount sent unexpected number of bytes");

            // Send all files with hashes to the client
            for (int i = 0; i < diffFileCount; i++) {
              sendSingleFile(clientSock, diffFiles[i].fileName, diffFiles[i].fileNameBytes);
            }

            free(diffFiles);
            diffFiles = NULL;
          } else if (command == 4) {
              /* ---------- LEAVE ---------- */
              if (serverFiles != NULL) {
                free(serverFiles);
                serverFiles = NULL;
              }

              close(clientSock);
              break;
          } else {
              /* ---------- Invalid option ---------- */
              printf("Client send invalid option. Exiting...\n");
              close(clientSock);
              break;
          }
        }
      }

      close(serverSock);
      return 0;
}

void fatal_error(char *message)
{
  perror(message);
  exit(1);
}

// Returns null-terminated SHA-256 hash
char* calculateSHA256(const char* filePath){
      FILE* file = fopen(filePath, "rb");

      if (!file) {
        fatal_error("fopen() failed");
      }

      // Initialize EVP context for SHA256
      EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

      if (mdctx == NULL) {
        fclose(file);
        fatal_error("EVP_MD_CTX_new() failed");
      }

      // Initialize SHA256 algorithm
      if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        fatal_error("EVP_DigestInit_ex() failed");
      }

      // Read the file in chunks and update the hash calculation
      unsigned char buffer[FILE_READ_BUFSIZE];
      size_t bytesRead;
      while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
          EVP_MD_CTX_free(mdctx);
          fclose(file);
          fatal_error("EVP_DigestUpdate() failed");
        }
      }

      // Finalize Hash Calculation
      unsigned char hash[EVP_MAX_MD_SIZE];
      unsigned int hashLength;
      if(EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1){
        perror("EVP_DigestFinal_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
      }

      // Convert hash to hexadecimal
      char* hashString = malloc(hashLength * 2 + 1);

      if(hashString == NULL){
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        fatal_error("malloc() failed for hashString");
      }

      memset(hashString, 0, hashLength * 2 + 1);

      for(unsigned int i = 0; i < hashLength; i++){
        sprintf(hashString + (i * 2), "%02x", hash[i]);
      }

      // Null-terminate hash string
      hashString[hashLength * 2] = '\0';
      EVP_MD_CTX_free(mdctx);
      fclose(file);

      return hashString;
}

// Function to get file names
ListMessageResponse* getFileNamesAndHashes(uint8_t *fileCount) {
    DIR *currentDir;
    struct dirent *entry;
    char filePath[1024];
    int capacity = 10; // Initial capacity for storing file info
    uint8_t currFileCount = 0;

    ListMessageResponse* fileInfos = malloc(capacity * sizeof(ListMessageResponse));

    if (fileInfos == NULL) {
        fatal_error("malloc");
    }

    memset(fileInfos, 0, capacity * sizeof(ListMessageResponse));

    if ((currentDir = opendir(DATA_DIR)) == NULL) {
        free(fileInfos);
        fileInfos = NULL;
        fatal_error("opendir() error");
    }
    
    // Loop through each entry in the directory
    while ((entry = readdir(currentDir)) != NULL) {
        snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, entry->d_name);
        struct stat fileStat;

        if (stat(filePath, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
            // Double size if capacity is reached
            if (currFileCount >= capacity) {
                int newCapacity = capacity * 2;
                ListMessageResponse* temp = realloc(fileInfos, newCapacity * sizeof(ListMessageResponse));

                if (temp == NULL) {
                    perror("realloc");
                    closedir(currentDir);
                    free(fileInfos);
                    return NULL;
                }

                memset(temp + capacity, 0, capacity * sizeof(ListMessageResponse));

                fileInfos = temp;
                capacity = newCapacity;
            }

            // Copy file name into struct
            uint8_t fileNameBytes = (uint8_t)(strlen(entry->d_name) + 1); // +1 for null terminator
            strncpy(fileInfos[currFileCount].fileName, entry->d_name, fileNameBytes);
            fileInfos[currFileCount].fileNameBytes = fileNameBytes;

            // Calculate and copy SHA-256 hash
            char* sha256 = calculateSHA256(filePath);
            uint8_t fileHashBytes = (uint8_t)(strlen(sha256) + 1); // +1 for null terminator

            if (sha256 != NULL) {
                strncpy(fileInfos[currFileCount].fileHash, sha256, fileHashBytes);
                fileInfos[currFileCount].fileHashBytes = fileHashBytes;
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

// Send single file to client
void sendSingleFile(int clientSock, const char *fileName, uint8_t fileNameBytes) {
    char *sndBuf;
    char filePath[RCVBUFSIZE];

    snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, fileName);
    int file_fd = open(filePath, O_RDONLY);

    if (file_fd == -1) {
      fatal_error("Failed to open file on server");
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
      close(file_fd);
      fatal_error("Failed to get file stats");
    }

    uint32_t fileSize = file_stat.st_size;
    printf("File size: %d\n", fileSize);

    // Prepare buffer
    int headerMessageSize = sizeof(uint8_t) + RCVBUFSIZE + sizeof(uint32_t);
    sndBuf = (char *)malloc(headerMessageSize);

    if (sndBuf == NULL) {
      close(file_fd);
      fatal_error("malloc() failed for sndBuf");
    }

    memset(sndBuf, 0, headerMessageSize);

    // Write fileNameBytes, fileName, and fileContentsBytes to buffer
    int offset = 0;
    memcpy(sndBuf, &fileNameBytes, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(sndBuf + offset, fileName, fileNameBytes);
    offset += RCVBUFSIZE;
    memcpy(sndBuf + offset, &fileSize, sizeof(uint32_t));

    // Send file header fields to client
    int totalBytesSent = 0;
    int bytesSent;

    while (totalBytesSent < headerMessageSize) {
        bytesSent = send(clientSock, sndBuf + totalBytesSent, headerMessageSize - totalBytesSent, 0);

        if (bytesSent < 0) {
          fatal_error("send() failed");
        } else if (bytesSent == 0) {
          fatal_error("Connection closed by client (or something).\n");
        }

        totalBytesSent += bytesSent;
    }

    free(sndBuf);

    // Prepare buffer for file contents
    sndBuf = (char *)malloc(fileSize);

    if (sndBuf == NULL) {
      close(file_fd);
      fatal_error("malloc() failed for sndBuf");
    }
    
    memset(sndBuf, 0, fileSize);

    // Read in file content to buffer
    int totalBytesRead = 0;
    int bytesRead;

    while (totalBytesRead < fileSize) {
      if ((bytesRead = read(file_fd, sndBuf + totalBytesRead, fileSize - totalBytesRead)) > 0) {
        totalBytesRead += bytesRead;
      } else if (bytesRead < 0) {
        free(sndBuf);
        close(file_fd);
        fatal_error("read() failed");
      } else if (bytesRead == 0 && totalBytesRead < fileSize) {
        free(sndBuf);
        close(file_fd);
        fatal_error("read() ended with totalBytesRead < fileSize");
      }
    }

    printf("Total bytes read: %d\n", totalBytesRead);

    if (bytesRead < 0) {
      free(sndBuf);
      close(file_fd);
      fatal_error("read() failed");
    }

    close(file_fd);

    // Send buffer to client
    totalBytesSent = 0;

    while (totalBytesSent < fileSize) {
        bytesSent = send(clientSock, sndBuf + totalBytesSent, fileSize - totalBytesSent, 0);

        if (bytesSent < 0) {
          fatal_error("send() failed");
        }
        else if (bytesSent == 0) {
          fatal_error("Connection closed by client (or something).\n");
        }

        totalBytesSent += bytesSent;
    }

    printf("Total bytes sent: %d\n", totalBytesSent);
    free(sndBuf);
}