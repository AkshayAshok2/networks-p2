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
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#define RCVBUFSIZE 512		/* The receive buffer size */
#define SNDBUFSIZE 512		/* The send buffer size */
#define BUFSIZE 40		/* Your name can be as many as 40 chars*/
#define DATA_DIR "./server_files"
#define FILE_READ_BUFSIZE 1024

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

void fatal_error(char *message)
{
  perror(message);
  exit(1);
}

ListMessageResponse* getFileNamesAndHashes(uint8_t* fileCount);
void sendSingleFile(int clientSock, const char *fileName, uint8_t fileNameBytes);

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

      char *rcvBuf;			// Buff to store requested files from client
      EVP_MD_CTX *mdctx;				// Digest data structure declaration
      const EVP_MD *md;				// Digest data structure declaration 
      int md_len;					// Digest data structure size tracking

      ListMessageResponse *serverFiles;

      servPort = 25000;

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

      // Outer loop to handle new incoming connections
      while (1) {
        clntLen = sizeof(client_addr);
        if ((clientSock = accept(serverSock, (struct sockaddr *) &client_addr, &clntLen)) < 0)
          fatal_error("accept() failed");

        // Inner loop to process commands on existing connection
        while (1) {
          int bytesReceived;
          uint8_t switchValue;

          if ((bytesReceived = recv(clientSock, &switchValue, 1, 0)) < 0)
            fatal_error("recv() failed");
          else if (bytesReceived == 0)
            fatal_error("Connection closed by client.");

          printf("Received menu choice: %u\n", switchValue);

          switch (switchValue)
          {
            case 1:
              /* ---------- LIST ---------- */
              serverFiles = getFileNamesAndHashes(&fileCount);

              if (serverFiles == NULL)
                fatal_error("getFileNamesAndHashes() failed");

              int totalSize = sizeof(uint8_t) + fileCount * sizeof(ListMessageResponse);
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
                memcpy(buffer + offset, &serverFiles[i], sizeof(ListMessageResponse));
                offset += sizeof(ListMessageResponse);
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
              break;
            case 3:
              /* ---------- PULL ---------- */
              uint8_t diffFileCount;
              uint8_t bytesReceived = recv(clientSock, diffFileCount, sizeof(uint8_t), 0);

              if (bytesReceived < 0)
                fatal_error("Initial recv() failed");
              else if (bytesReceived == 0)
                fatal_error("Connection closed by server for first byte.\n");

              uint32_t totalMessageSize = diffFileCount * sizeof(DiffMessage);

              if (rcvBuf != NULL)
                free(rcvBuf);

              rcvBuf = (char *)malloc(totalMessageSize);

              if (rcvBuf == NULL)
                fatal_error("malloc() failed for rcvBuf");

              memset(rcvBuf, 0, totalMessageSize);
              int totalBytesReceived = 0;

              while (totalBytesReceived < totalMessageSize) {
                bytesReceived = recv(clientSock, rcvBuf + totalBytesReceived, totalMessageSize - totalBytesReceived, 0);

                if (bytesReceived < 0)
                  fatal_error("recv() for file names and hashes failed");
                else if (bytesReceived == 0)
                  printf("??? stopping here.\n");
                  break;

                totalBytesReceived += bytesReceived;
              }

              DiffMessage *diffFiles = (DiffMessage *)malloc(totalMessageSize);

              if (diffFiles == NULL)
                fatal_error("malloc() failed for serverFiles");

              int offset = 0;

              // Deserialize each listMessageResponse
              for (int i = 0; i < diffFileCount; i++) {
                DiffMessage *diffFile = &diffFiles[i];

                memset(diffFile, 0, sizeof(DiffMessage));

                // Deserialize fileNameBytes
                memcpy(&diffFile->fileHashBytes, rcvBuf + offset, sizeof(uint8_t));
                offset += sizeof(uint8_t);

                // Deserialize fileName
                memcpy(diffFile->fileHash, rcvBuf + offset, diffFile->fileHashBytes);
                offset += RCVBUFSIZE;

                // Deserialize fileHashBytes
                memcpy(&diffFile->fileHashBytes, rcvBuf + offset, sizeof(uint8_t));
                offset += sizeof(uint8_t);

                // Deserialize fileHash
                memcpy(diffFile->fileHash, rcvBuf + offset, diffFile->fileHashBytes);
                offset += RCVBUFSIZE;
              }

              free(rcvBuf);

              // Send number of files being sent to client
              if (send(clientSock, &diffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t))
                fatal_error("send() for diffFileCount sent unexpected number of bytes");

              // Send all files with hashes to the client
              for (int i = 0; i < diffFileCount; i++) {
                sendSingleFile(clientSock, diffFiles[i].fileName, diffFiles[i].fileNameBytes);
              }

              free(diffFiles);
              break;
            case 4:
              /* ---------- LEAVE ---------- */
              if (serverFiles != NULL) {
                free(serverFiles);
              }

              close(clientSock);
              break;
            default:
              /* ---------- Invalid option ---------- */
              printf("Client send invalid option. Exiting...\n");
              close(clientSock);
              break;
          }

          if (switchValue == 4)
            break;
        }
      }

      close(serverSock);
      return 0;
}

// Returns null-terminated SHA-256 hash
char* calculateSHA256(const char* filePath){
      //open file in binary mode
      FILE* file = fopen(filePath, "rb");

      if (!file) {
        perror("fopen");
        return NULL;
      }

      // Initialize EVP context for SHA256
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

      // Convert hash to hexadecimal
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
        perror("malloc");
        return NULL;
    }

    memset(fileInfos, 0, capacity * sizeof(ListMessageResponse));

    if ((currentDir = opendir(DATA_DIR)) == NULL) {
        perror("opendir() error");
        free(fileInfos);
        return NULL;
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
                memset(temp + capacity, 0, capacity * sizeof(ListMessageResponse));

                if (temp == NULL) {
                    perror("realloc");
                    closedir(currentDir);
                    free(fileInfos);
                    return NULL;
                }

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
    int file_fd = open(fileName, O_RDONLY);

    if (file_fd == -1) {
      fatal_error("Failed to open file on server");
    }

    struct stat file_stat;
    if (fstat(file_fd, &file_stat) < 0) {
      close(file_fd);
      fatal_error("Failed to get file stats");
    }

    uint32_t fileSize = file_stat.st_size;

    if (sndBuf == NULL) {
      close(file_fd);
      fatal_error("malloc() failed");
    }

    send(clientSock, &fileSize, sizeof(uint32_t), 0);

    PullMessageResponse fileToSend;
    fileToSend.fileNameBytes = fileNameBytes;
    strncpy(fileToSend.fileName, fileName, fileNameBytes);
    fileToSend.fileContentsBytes = fileSize;

    // Prepare buffer
    int totalMessageSize = sizeof(uint8_t) + fileNameBytes + sizeof(uint32_t) + fileSize;
    sndBuf = (char *)malloc(totalMessageSize);
    memset(sndBuf, 0, totalMessageSize);

    // Write fileNameBytes, fileName, and fileContentsBytes to buffer
    int offset = 0;
    memcpy(sndBuf, &fileToSend.fileNameBytes, sizeof(uint8_t));
    offset += sizeof(uint8_t);
    memcpy(sndBuf + offset, fileToSend.fileName, fileToSend.fileNameBytes);
    offset += fileToSend.fileNameBytes;
    memcpy(sndBuf + offset, &fileToSend.fileContentsBytes, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    int totalBytesRead = 0;
    int bytesRead;

    while (totalBytesRead < fileSize) {
      if ((bytesRead = read(file_fd, sndBuf + offset + totalBytesRead, fileSize - totalBytesRead)) > 0) {
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

    if (bytesRead < 0) {
      free(sndBuf);
      close(file_fd);
      fatal_error("read() failed");
    }

    close(file_fd);

    // Send buffer to client
    int totalBytesSent = 0;
    int bytesSent;

    while (totalBytesSent < totalMessageSize) {
        bytesSent = send(clientSock, sndBuf + totalBytesSent, totalMessageSize - totalBytesSent, 0);

        if (bytesSent < 0) {
            fatal_error("send() failed");
        }
        else if (bytesSent == 0) {
            fatal_error("Connection closed by client (or something).\n");
        }

        totalBytesSent += bytesSent;
    }

    free(sndBuf);
}