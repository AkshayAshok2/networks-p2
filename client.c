/*///////////////////////////////////////////////////////////
*
* FILE:		client.c
* AUTHORS:	Akshay Ashok and Joshua Thomas
* PROJECT:	CNT 4007 Project 2 - Professor Traynor
* DESCRIPTION:	Network Client Code
*
*////////////////////////////////////////////////////////////

/* Included libraries */
#include <stdio.h>		    /* for printf() and fprintf() */
#include <sys/socket.h>		    /* for socket(), connect(), send(), and recv() */
#include <arpa/inet.h>		    /* for sockaddr_in and inet_addr() */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>	    /* for OpenSSL EVP digest libraries/SHA256 */
#include <openssl/sha.h>

/* Constants */
#define RCVBUFSIZE 512		    /* The receive buffer size */
#define MDLEN 32
#define DATA_DIR "./client_files"
#define FILE_READ_BUFSIZE 1024

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
    ListMessageResponse *clientFiles, 
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

    int servPort = 25000;
    char *servIP = "127.0.0.1";

    uint8_t serverFileCount;
    uint8_t clientFileCount;
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
    serv_addr.sin_port          = htons(servPort);
    serv_addr.sin_addr.s_addr   = inet_addr(servIP);

    /* Establish connection to the server */
    if (connect(clientSock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        fatal_error("connect() failed");

    printf("Welcome to UFmyMusic!\n");
    
    while (1) {
        printf("\nSelect an option:\n1. LIST\n2. DIFF\n3. PULL\n4. LEAVE\n");
        uint8_t option;
        scanf("%hhu", &option);

        switch (option) {
            case 1:
                /*---------- LIST ----------*/
                if (serverFiles != NULL) {
                    free(serverFiles);
                    serverFiles = NULL;
                }

                serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);

                if (serverFiles == NULL) {
                    printf("serverFiles is NULL. Exiting...\n");
                    break;
                } else if (serverFileCount == 0) {
                    printf("serverFileCount is 0. Exiting...\n");
                    break;
                }

                // Print the received files
                for (int i = 0; i < serverFileCount; i++) {
                    printf("File %d:\n", i + 1);
                    printf("Name: %s\n", serverFiles[i].fileName);
                    printf("Hash: %s\n", serverFiles[i].fileHash);
                }

                break;
            case 2:
                /*---------- DIFF ----------*/
                if (serverFileCount == 0 || serverFiles == NULL) {
                    printf("LIST has not been called yet. Doing so now...\n");

                    if (serverFiles != NULL) {
                        free(serverFiles);
                        serverFiles = NULL;
                    }

                    serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);

                    if (serverFiles == NULL || serverFileCount == 0) {
                        printf("LIST failed. Exiting...\n");
                        break;
                    }
                }

                if (clientFiles != NULL) {
                    free(clientFiles);
                    clientFiles = NULL;
                }

                diffFiles = DIFF(
                    serverFiles, 
                    serverFileCount, 
                    clientFiles, 
                    &clientFileCount,
                    &diffFileCount,
                    0
                );
                break;
            case 3:
                /*---------- PULL ----------*/
                if (serverFileCount == 0 || serverFiles == NULL) {
                    printf("LIST has not been called yet. Doing so now...\n");

                    if (serverFiles != NULL) {
                        free(serverFiles);
                        serverFiles = NULL;
                    }

                    serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);

                    if (serverFiles == NULL || serverFileCount == 0) {
                        printf("LIST failed. Exiting...\n");
                        break;
                    }
                }

                if (clientFileCount == 0 || clientFiles == NULL || diffFiles == NULL) {
                    printf("DIFF has not been called yet. Doing so now...\n");

                    if (clientFiles != NULL) {
                        free(clientFiles);
                        clientFiles = NULL;
                    }

                    if (diffFiles != NULL) {
                        free(diffFiles);
                        diffFiles = NULL;
                    }

                    diffFiles = DIFF(
                        serverFiles, 
                        serverFileCount, 
                        clientFiles, 
                        &clientFileCount,
                        &diffFileCount, 
                        1
                    );

                    if (clientFiles == NULL || clientFileCount == 0) {
                        printf("Failed to load client files. Exiting...\n");
                        break;
                    }
                }

                PULL(clientSock, diffFileCount, diffFiles, rcvBuf);
                break;
            case 4:
                /*---------- LEAVE ----------*/
                // Send 4 to the server
                if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
                    fatal_error("send() sent unexpected number of bytes");

                // Free the allocated memory for each fileName and fileHash
                if (serverFiles != NULL) {
                    free(serverFiles);
                }

                if (clientFiles != NULL) {
                    free(clientFiles);
                }

                if (diffFiles != NULL) {
                    free(diffFiles);
                }

                close(clientSock);
                return 0;
            default:
                printf("Invalid option. Please try again.\n");
                continue;
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

    uint32_t totalMessageSize = *serverFileCount * sizeof(ListMessageResponse);

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
    
    ListMessageResponse *serverFiles = (ListMessageResponse *)malloc(totalMessageSize);

    if (serverFiles == NULL)
        fatal_error("malloc() failed for serverFiles");

    int offset = 0;

    // Deserialize each listMessageResponse
    for (int i = 0; i < *serverFileCount; i++) {
        ListMessageResponse *response = &serverFiles[i];

        memset(response, 0, sizeof(ListMessageResponse));

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
        perror("malloc");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return NULL;
    }

    for (unsigned int i = 0; i < hashLength; i++) {
        sprintf(hashString + (i * 2), "%02x", hash[i]);
    }

    // Null-terminate hash string
    hashString[hashLength * 2] = '\0';
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return hashString;
}

/* Returns populated list of `listMessagResponse` structs */
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
            if (*fileCount >= capacity) {
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

            // Copy file name into struct (`d_name` already null-terminated)
            uint8_t fileNameBytes = (uint8_t)(strlen(entry->d_name) + 1); // +1 for null terminator
            strncpy(fileInfos[currFileCount].fileName, entry->d_name, fileNameBytes);
            fileInfos[currFileCount].fileNameBytes = fileNameBytes;

            // Calculate and copy SHA-256 hash (already null-terminated)
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

/* Function to handle DIFF command */
DiffMessage *DIFF(
    ListMessageResponse *serverFiles, 
    uint8_t serverFileCount, 
    ListMessageResponse *clientFiles, 
    uint8_t *clientFileCount,
    uint8_t *diffFileCount, 
    uint8_t suppressOutput
) {
    clientFiles = getFileNamesAndHashes(clientFileCount);
    int overlapCount = 0;
    DiffMessage *diffFiles = NULL;

    if (clientFiles == NULL || serverFiles == NULL) {
        fatal_error("One of the file lists is NULL. Exiting...\n");
    }

    if (!suppressOutput) {
        printf("Files on both machines:\n");
        for (int i = 0; i < serverFileCount; i++) {
            for (int j = 0; j < *clientFileCount; j++) {
                if (strcmp(serverFiles[i].fileHash, clientFiles[j].fileHash) == 0) {
                    printf("File: %s\n", serverFiles[i].fileName);
                    overlapCount++;
                }
            }
        }
    }

    *diffFileCount = serverFileCount - overlapCount;

    if (serverFileCount > overlapCount) {
        int diffTotal = serverFileCount - overlapCount;

        if (!suppressOutput)
            printf("\nFiles missing on the client:\n");
        diffFiles = malloc(diffTotal * sizeof(DiffMessage));
        memset(diffFiles, 0, diffTotal * sizeof(DiffMessage));
        int diffCount = 0;

        for (int i = 0; i < serverFileCount; i++) {
            int found = 0;
            for (int j = 0; j < *clientFileCount; j++) {
                if (strcmp(serverFiles[i].fileHash, clientFiles[j].fileHash) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (!suppressOutput)
                    printf("File: %s\n", serverFiles[i].fileName);

                strncpy(diffFiles[diffCount].fileName, serverFiles[i].fileName, serverFiles[i].fileNameBytes);
                diffFiles[diffCount].fileNameBytes = serverFiles[i].fileNameBytes;
                strncpy(diffFiles[diffCount].fileHash, serverFiles[i].fileHash, serverFiles[i].fileHashBytes);
                diffFiles[diffCount].fileHashBytes = serverFiles[i].fileHashBytes;

                diffCount++;
            }
        }
    }
    
    fflush(stdout);

    if (serverFileCount > overlapCount) {
        return diffFiles;
    } else {
        return NULL;
    }
}

//receive a file and its hash from the server
void receive_file_with_hash(int sock, const char *file_name){
    char buffer[FILE_READ_BUFSIZE];
    ssize_t bytes_received;
    size_t file_size;
    size_t total_bytes_received = 0;

    recv(sock, &file_size, sizeof(file_size), 0);
    printf("Receiving file: %s (%zu bytes)\n", file_name, file_size);

    FILE *fp = fopen(file_name, "wb");
    if(fp == NULL){
        perror("Error opening file for writing");
        return;
    }

    // Receive the file data
    while((bytes_received = recv(sock, buffer, FILE_READ_BUFSIZE, 0)) > 0){
        fwrite(buffer, sizeof(char), bytes_received, fp);
        total_bytes_received += bytes_received;
        if(total_bytes_received >= file_size){
            break;
        }
    }
    fclose(fp);
    printf("File %s received succesfully\n", file_name);
}


/* Function to handle PULL command */
void PULL(int clientSock, uint8_t *diffFileCount, DiffMessage *diffFiles, char *rcvBuf) {
    uint8_t option = 3;

    // Send 3 to the server
    if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
        fatal_error("send() for option sent unexpected number of bytes");

    int totalSize = sizeof(uint8_t) + *diffFileCount * sizeof(DiffMessage);
    char *buffer = (char *)malloc(totalSize);

    if (buffer == NULL) {
        fatal_error("malloc() failed for buffer");
    }

    memset(buffer, 0, totalSize);

    // Serialize the data
    int offset = 0;
    memcpy(buffer, diffFileCount, sizeof(uint8_t));
    offset += sizeof(uint8_t);

    for (int i = 0; i < *diffFileCount; i++) {
        memcpy(buffer + offset, &diffFiles[i], sizeof(DiffMessage));
        offset += sizeof(DiffMessage);
    }

    // Send the number of files to be pulled
    if (send(clientSock, diffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t))
        fatal_error("send() for diffFileCount sent unexpected number of bytes");

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
    uint8_t serverDiffFileCount;

    // Receive the number of files to be received from server
    if (recv(clientSock, &serverDiffFileCount, sizeof(uint8_t), 0) != sizeof(uint8_t)
    || serverDiffFileCount != *diffFileCount)
        fatal_error("recv() for diffFileCount received unexpected number of bytes or wrong value");

    // Receive all files
    for (int i = 0; i < serverDiffFileCount; i++) {
        int totalBytesReceived;
        int bytesReceived;
        uint8_t fileNameBytes;
        char *fileName;
        uint32_t fileContentsBytes;
        char *fileContents;

        // Receive fileNameBytes
        if (recv(clientSock, &fileNameBytes, sizeof(uint8_t), 0) != sizeof(uint8_t))
            fatal_error("recv() for fileNameBytes failed");

        // Receive fileName
        fileName = (char *)malloc(fileNameBytes);
        memset(fileName, 0, fileNameBytes);
        totalBytesReceived = 0;

        while (totalBytesReceived < fileNameBytes) {
            bytesReceived = recv(clientSock, fileName + totalBytesReceived, fileNameBytes - totalBytesReceived, 0);

            if (bytesReceived < 0)
                fatal_error("recv() for file names and hashes failed");
            else if (bytesReceived == 0)
                printf("??? stopping here.\n");
                break;

            totalBytesReceived += bytesReceived;
        }

        // Receive fileContentsBytes
        totalBytesReceived = 0;

        while (totalBytesReceived < sizeof(uint32_t)) {
            bytesReceived = recv(clientSock, &fileContentsBytes + totalBytesReceived, sizeof(uint32_t) - totalBytesReceived, 0);

            if (bytesReceived < 0)
                fatal_error("recv() for fileContentsBytes failed");
            else if (bytesReceived == 0)
                printf("??? stopping here.\n");
                break;

            totalBytesReceived += bytesReceived;
        }

        // Receive fileContents
        fileContents = (char *)malloc(fileContentsBytes);
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
        FILE *fp = fopen(fileName, "wb");

        if (fp == NULL)
            fatal_error("Error opening file for writing");

        if (fwrite(fileContents, 1, fileContentsBytes, fp) != fileContentsBytes)
            fatal_error("fwrite() failed to write whole file");

        fclose(fp);
        free(fileName);
        free(fileContents);
    }

    return NULL;
}