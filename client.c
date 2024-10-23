/*///////////////////////////////////////////////////////////
*
* FILE:		client.c
* AUTHORS:	Akshay Ashok and Joshua Thomas
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Client Code
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

/* Constants */
#define RCVBUFSIZE 512
#define MDLEN 32
#define DATA_DIR "./client_files"
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
    uint8_t fileHashBytes;
    char fileHash[RCVBUFSIZE];
    uint32_t fileContentsBytes;
    char fileContents[RCVBUFSIZE];
} PullMessageResponse;

typedef struct {
    uint8_t fileNameBytes;
    char fileName[RCVBUFSIZE];
    uint8_t fileHashBytes;
    char fileHash[RCVBUFSIZE];
} DiffMessage;

/* Function prototypes */
void fatal_error(char *message);
ListMessageResponse *LIST(int clientSock, uint8_t *serverFileCount, char *rcvBuf);
char* calculateSHA256(const char* filePath);
ListMessageResponse* getFileNamesAndHashes(uint8_t *fileCount);
DiffMessage *DIFF(
    ListMessageResponse *serverFiles, 
    uint8_t serverFileCount, 
    ListMessageResponse **clientFiles, 
    uint8_t *clientFileCount, 
    uint8_t *diffFileCount, 
    uint8_t suppressOutput
);
void receive_file_with_hash(int sock, const char *file_name);
void PULL(int clientSock, uint8_t *diffFileCount, DiffMessage *diffFiles, char *rcvBuf);

/* The main function */
int main(int argc, char *argv[])
{
    int clientSock;		    /* socket descriptor */
    int msgLen;
    struct sockaddr_in serv_addr;   /* The server address */
    struct sockaddr_in client_addr; /* The client address */

    char *rcvBuf;	    /* Receive Buffer */
    char *servIP = "127.0.0.1";

    uint8_t serverFileCount;
    uint8_t clientFileCount;
    uint8_t isDiff = 1;
    uint8_t diffFileCount;

    ListMessageResponse *serverFiles;
    ListMessageResponse *clientFiles;
    DiffMessage *diffFiles;

    /* Create a new TCP socket*/
    if ((clientSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        fatal_error("socket() failed");

    /* Construct the server address structure */
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family        = AF_INET;
    serv_addr.sin_port          = htons(SERVER_PORT);
    serv_addr.sin_addr.s_addr   = inet_addr(servIP);

    /* Establish connection to the server */
    if (connect(clientSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        fatal_error("connect() failed");

    printf("Welcome to UFmyMusic!\n");
    
    while (1) {
        printf("\nSelect an option:\n1. LIST\n2. DIFF\n3. PULL\n4. LEAVE\n");
        uint8_t option = 0;
        scanf("%hhu", &option);

        if (option == 1) {
            /*---------- LIST ----------*/
            if (serverFiles != NULL) {
                free(serverFiles);
                serverFiles = NULL;
            }

            serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);

            if (serverFiles == NULL) {
                fatal_error("serverFiles is NULL. Exiting...\n");
                break;
            } else if (serverFileCount == 0) {
                fatal_error("serverFileCount is 0. Exiting...\n");
                break;
            }

            // Print the received files
            for (int i = 0; i < serverFileCount; i++) {
                printf("File %d:\n", i + 1);
                printf("Name: %s\n", serverFiles[i].fileName);
                printf("Hash: %s\n", serverFiles[i].fileHash);
            }
        } else if (option == 2) {
            /*---------- DIFF ----------*/
            if (serverFileCount == 0 || serverFiles == NULL) {
                printf("LIST has not been called yet. Please call that first.\n");
                continue;
            }

            if (clientFiles != NULL) {
                free(clientFiles);
                clientFiles = NULL;
            }

            diffFiles = DIFF(
                serverFiles, 
                serverFileCount, 
                &clientFiles, 
                &clientFileCount,
                &diffFileCount,
                0
            );

            if (clientFiles == NULL)
                fatal_error("DIFF() from option 2 failed");
        } else if (option == 3) {
            /*---------- PULL ----------*/
            if (clientFiles == NULL) {
                printf("DIFF has not been called yet. Please call that first.\n");
                continue;
            }

            if (isDiff)
                PULL(clientSock, &diffFileCount, diffFiles, rcvBuf);
            else
                printf("No files to pull.\n");
        } else if (option == 4) {
            /*---------- LEAVE ----------*/
            // Send 4 to the server
            if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
                fatal_error("send() sent unexpected number of bytes");

            // Free the allocated memory for each fileName and fileHash
            // if (serverFiles != NULL) {
            //     free(serverFiles);
            //     serverFiles = NULL;
            // }

            // if (clientFiles != NULL) {
            //     free(clientFiles);
            //     clientFiles = NULL;
            // }

            // if (diffFiles != NULL) {
            //     free(diffFiles);
            //     diffFiles = NULL;
            // }

            close(clientSock);
            return 0;
        } else {
            printf("Invalid option. Please try again.\n");
        }
    }

    return 0;
}

/* Function to handle errors */
void fatal_error(char *message)
{
    perror(message);
    exit(1);
}

/* Function to handle LIST command */
ListMessageResponse *LIST(int clientSock, uint8_t *serverFileCount, char *rcvBuf) {
    // Clean up if previously run
    if (rcvBuf != NULL) {
        free(rcvBuf);
        rcvBuf = NULL;
    }

    uint8_t option = 1;

    if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
        fatal_error("send() sent unexpected number of bytes");

    uint8_t bytesReceived = recv(clientSock, serverFileCount, sizeof(uint8_t), 0);

    if (bytesReceived < 0)
        fatal_error("First recv() failed");
    else if (bytesReceived == 0)
        fatal_error("Connection closed by server for first byte.\n");

    uint32_t totalMessageSize = *serverFileCount * (2 * sizeof(uint8_t) + 2 * RCVBUFSIZE);

    if (rcvBuf != NULL) {
        free(rcvBuf);
        rcvBuf = NULL;
    }

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
    
    ListMessageResponse *serverFiles = (ListMessageResponse *)malloc(*serverFileCount * sizeof(ListMessageResponse));

    if (serverFiles == NULL)
        fatal_error("malloc() failed for serverFiles");

    memset(serverFiles, 0, *serverFileCount * sizeof(ListMessageResponse));
    int offset = 0;

    // Deserialize each listMessageResponse
    for (int i = 0; i < *serverFileCount; i++) {
        ListMessageResponse *response = &serverFiles[i];

        // Deserialize fileNameBytes
        memcpy(&response->fileNameBytes, rcvBuf + offset, sizeof(uint8_t));
        offset += sizeof(uint8_t);

        // Deserialize fileName
        memcpy(response->fileName, rcvBuf + offset, response->fileNameBytes);
        offset += RCVBUFSIZE;

        // Deserialize fileHashBytes
        memcpy(&response->fileHashBytes, rcvBuf + offset, sizeof(uint8_t));
        offset += sizeof(uint8_t);

        // Deserialize fileHash
        memcpy(response->fileHash, rcvBuf + offset, response->fileHashBytes);
        offset += RCVBUFSIZE;
    }

    free(rcvBuf);
    rcvBuf = NULL;
    return serverFiles;
}

/* Returns null-terminated SHA256 hash */
char* calculateSHA256(const char* filePath){
    // Open file in binary mode
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

    // Initialize SHA256 algorithm
    if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1){
        perror("EVP_DigestInit_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    // Read the file in chunks and update the hash calculation
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

    // Finalize Hash Calculation
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength;

    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        perror("EVP_DigestFinal_ex");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    // Convert hash to hexadecimal
    char* hashString = malloc(hashLength * 2 + 1);

    if (hashString == NULL) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        fatal_error("malloc() failed for hashString");
    }

    memset(hashString, 0, hashLength * 2 + 1);

    for (unsigned int i = 0; i < hashLength; i++) {
        sprintf(hashString + (i * 2), "%02x", hash[i]);
    }

    // Null-terminate hash string
    hashString[hashLength * 2] = '\0';
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return hashString;
}

/* Returns populated list of `listMessageResponse` structs */
ListMessageResponse* getFileNamesAndHashes(uint8_t *fileCount) {
    DIR *currentDir;
    struct dirent *entry;
    char filePath[1024];
    int capacity = 10; // Initial capacity for storing file info
    uint8_t currFileCount = 0;

    printf("getFileNamesAndHashes entered\n");
    ListMessageResponse* fileInfos = malloc(capacity * sizeof(ListMessageResponse));

    if (fileInfos == NULL) {
        fatal_error("malloc() failed for fileInfos");
    }

    memset(fileInfos, 0, capacity * sizeof(ListMessageResponse));
    
    // HERE!
    if ((currentDir = opendir(DATA_DIR)) == NULL) { // this line
        printf("Do we enter here?\n"); // no
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
            if (*fileCount >= capacity) {
                int newCapacity = capacity * 2;
                ListMessageResponse* temp = realloc(fileInfos, newCapacity * sizeof(ListMessageResponse));
                printf("here?\n");
                memset(temp + capacity, 0, capacity * sizeof(ListMessageResponse));

                if (temp == NULL) {
                    closedir(currentDir);
                    free(fileInfos);
                    fileInfos = NULL;
                    fatal_error("realloc() failed");
                }

                fileInfos = temp;
                capacity = newCapacity;
            }

            // Copy file name into struct (`d_name` already null-terminated)
            uint8_t fileNameBytes = (uint8_t)(strlen(entry->d_name) + 1); // +1 for null terminator
            strcpy(fileInfos[currFileCount].fileName, entry->d_name);
            fileInfos[currFileCount].fileNameBytes = fileNameBytes;

            // Calculate and copy SHA-256 hash (already null-terminated)
            char* sha256 = calculateSHA256(filePath);
            uint8_t fileHashBytes = (uint8_t)(strlen(sha256) + 1); // +1 for null terminator

            if (sha256 != NULL) {
                strncpy(fileInfos[currFileCount].fileHash, sha256, fileHashBytes);
                fileInfos[currFileCount].fileHashBytes = fileHashBytes;
                free(sha256);
                sha256 = NULL;
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

/* Function to handle DIFF command */
DiffMessage *DIFF(
    ListMessageResponse *serverFiles, 
    uint8_t serverFileCount,
    ListMessageResponse **clientFiles, 
    uint8_t *clientFileCount,
    uint8_t *diffFileCount, 
    uint8_t suppressOutput
) {
    *clientFiles = getFileNamesAndHashes(clientFileCount);

    if (*clientFileCount == 0) {
        printf("No files found on the client. Exiting...\n");
        return NULL;
    }

    DiffMessage *diffFiles = NULL;

    if (*clientFiles == NULL || serverFiles == NULL) {
        fatal_error("One of the file lists is NULL");
    }

    if (!suppressOutput) {
        printf("Files on both machines:\n");
        for (int i = 0; i < serverFileCount; i++) {
            for (int j = 0; j < *clientFileCount; j++) {
                if (strcmp(serverFiles[i].fileHash, (*clientFiles)[j].fileHash) == 0) {
                    printf("File: %s\n", serverFiles[i].fileName);
                }
            }
        }
    }

    *diffFileCount = serverFileCount - *clientFileCount;

    if (*diffFileCount > 0) {
        if (!suppressOutput)
            printf("\nFiles missing on the client:\n");

        diffFiles = malloc(*diffFileCount * sizeof(DiffMessage));

        if (diffFiles == NULL)
            fatal_error("malloc() failed for diffFiles");

        memset(diffFiles, 0, *diffFileCount * sizeof(DiffMessage));
        int diffCount = 0;

        for (int i = 0; i < serverFileCount; i++) {
            int found = 0;
            for (int j = 0; j < *clientFileCount; j++) {
                if (strcmp(serverFiles[i].fileHash, (*clientFiles)[j].fileHash) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (!suppressOutput)
                    printf("File: %s\n", serverFiles[i].fileName);

                // printf("Length of file name: %ld\n", strlen(serverFiles[i].fileName));
                // printf("File name bytes: %d\n", serverFiles[i].fileNameBytes);
                // printf("Length of file hash: %ld\n", strlen(serverFiles[i].fileHash));
                // printf("File hash bytes: %d\n", serverFiles[i].fileHashBytes);

                strncpy(diffFiles[diffCount].fileName, serverFiles[i].fileName, RCVBUFSIZE);
                diffFiles[diffCount].fileName[serverFiles[i].fileNameBytes] = '\0';
                diffFiles[diffCount].fileNameBytes = serverFiles[i].fileNameBytes;

                strncpy(diffFiles[diffCount].fileHash, serverFiles[i].fileHash, RCVBUFSIZE);
                diffFiles[diffCount].fileHash[serverFiles[i].fileHashBytes] = '\0';
                diffFiles[diffCount].fileHashBytes = serverFiles[i].fileHashBytes;

                diffCount++;
            }
        }
    } else
        printf("No files missing on the client!\n");
    
    fflush(stdout);
    return diffFiles;
}

/* Function to handle PULL command */
void PULL(int clientSock, uint8_t *diffFileCount, DiffMessage *diffFiles, char *rcvBuf) {
    uint8_t option = 3;
    char *buffer;

    // Send 3 to the server
    if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
        fatal_error("send() for option sent unexpected number of bytes");

    // Send the number of files to be pulled
    if (send(clientSock, diffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t))
        fatal_error("send() for diffFileCount sent unexpected number of bytes");

    // Validate inputs
    if (diffFileCount == NULL || *diffFileCount == 0) {
        fatal_error("Invalid diffFileCount");
    }

    if (diffFiles == NULL) {
        fatal_error("Invalid diffFiles pointer");
    }

    size_t totalSize = *diffFileCount * (2 * sizeof(uint8_t) + 2 * RCVBUFSIZE);
    printf("Total size: %zu\n", totalSize);
    buffer = malloc(totalSize);

    if (buffer == NULL) {
        fatal_error("malloc() failed for buffer");
    }

    memset(buffer, 0, totalSize);

    // Serialize the data
    int offset = 0;
    for (int i = 0; i < *diffFileCount; i++) {
        memcpy(buffer + offset, &diffFiles[i].fileNameBytes, sizeof(uint8_t));
        offset += sizeof(uint8_t);
        memcpy(buffer + offset, diffFiles[i].fileName, diffFiles[i].fileNameBytes);
        offset += RCVBUFSIZE;
        memcpy(buffer + offset, &diffFiles[i].fileHashBytes, sizeof(uint8_t));
        offset += sizeof(uint8_t);
        memcpy(buffer + offset, diffFiles[i].fileHash, diffFiles[i].fileHashBytes);
        offset += RCVBUFSIZE;
    }

    // Send the data
    int totalBytesSent = 0;
    int bytesSent;

    while (totalBytesSent < totalSize) {
        bytesSent = send(clientSock, buffer + totalBytesSent, totalSize - totalBytesSent, 0);

        if (bytesSent < 0)
            fatal_error("send() failed");
        else if (bytesSent == 0)
            fatal_error("Connection closed somehow?\n");

        totalBytesSent += bytesSent;
    }

    free(buffer);
    buffer = NULL;
    uint8_t serverDiffFileCount;

    // Receive the number of files to be received from server
    if (recv(clientSock, &serverDiffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t)
    || serverDiffFileCount != *diffFileCount)
        fatal_error("recv() for diffFileCount received unexpected number of bytes or wrong value");

    // Receive all files
    for (int i = 0; i < serverDiffFileCount; i++) {
        int totalBytesReceived;
        int bytesReceived;
        char *fileHeader;
        char *fileContents;

        uint8_t fileNameBytes;
        char *fileName;
        uint32_t fileContentsBytes;

        // Receive header fields
        int headerBytes = sizeof(uint8_t) + RCVBUFSIZE + sizeof(uint32_t);
        fileHeader = (char *)malloc(headerBytes);

        if (fileHeader == NULL)
            fatal_error("malloc() failed for fileHeader");

        memset(fileHeader, 0, headerBytes);
        totalBytesReceived = 0;

        while (totalBytesReceived < headerBytes) {
            bytesReceived = recv(clientSock, fileHeader + totalBytesReceived, headerBytes - totalBytesReceived, 0);

            if (bytesReceived < 0)
                fatal_error("recv() for file names and hashes failed");
            else if (bytesReceived == 0)
                printf("??? stopping here.\n");
                break;

            totalBytesReceived += bytesReceived;
        }

        printf("Ideal bytes received: %d\n", headerBytes);
        printf("Total bytes received: %d\n", totalBytesReceived);

        // Deserialize header fields
        offset = 0;
        memcpy(&fileNameBytes, fileHeader + offset, sizeof(uint8_t));
        offset += sizeof(uint8_t);

        fileName = (char *)malloc(fileNameBytes);

        if (fileName == NULL)
            fatal_error("malloc() failed for fileName");
            
        memset(fileName, 0, fileNameBytes);
        memcpy(fileName, fileHeader + offset, fileNameBytes);
        offset += RCVBUFSIZE;

        memcpy(&fileContentsBytes, fileHeader + offset, sizeof(uint32_t));

        // Verify header fields
        printf("\nFile name bytes: %d\n", fileNameBytes);
        printf("File name: %s\n", fileName);
        printf("File contents bytes: %d\n", fileContentsBytes);

        // Receive fileContents
        fileContents = (char *)malloc(fileContentsBytes);

        if (fileContents == NULL)
            fatal_error("malloc() failed for fileContents");

        memset(fileContents, 0, fileContentsBytes);
        totalBytesReceived = 0;

        while (totalBytesReceived < fileContentsBytes) {
            bytesReceived = recv(clientSock, fileContents + totalBytesReceived, fileContentsBytes - totalBytesReceived, 0);

            if (bytesReceived < 0)
                fatal_error("recv() for fileContents failed");
            else if (bytesReceived == 0)
                printf("??? stopping here.\n");
                break;

            totalBytesReceived += bytesReceived;
        }

        // Write to file
        char filePath[RCVBUFSIZE];
        snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, fileName);
        printf("Attempting to open file: %s\n", filePath);
        FILE *fp = fopen(filePath, "wb");

        if (fp == NULL)
            fatal_error("Error opening file for writing");

        if (fwrite(fileContents, 1, fileContentsBytes, fp) != fileContentsBytes)
            fatal_error("fwrite() failed to write whole file");

        fclose(fp);
        free(fileName);
        fileName = NULL;
        free(fileContents);
        fileContents = NULL;
        free(fileHeader);
        fileHeader = NULL;
    }

    free(buffer);
    buffer = NULL;
    return;
}