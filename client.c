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
#define SNDBUFSIZE 512		    /* The send buffer size */
#define MDLEN 32
#define DATA_DIR "./client_files"
#define FILE_READ_BUFSIZE 1024

void fatal_error(char *message)
{
    perror(message);
    exit(1);
}

typedef struct {
    uint8_t fileNameBytes;
    char fileName[RCVBUFSIZE];
    uint8_t fileHashBytes;
    char fileHash[RCVBUFSIZE];
} listMessageResponse;

typedef struct {
    uint8_t fileHashBytes;
    char fileHash[RCVBUFSIZE];
    uint8_t fileContentsBytes;
    char fileContents[RCVBUFSIZE];
} pullMessageResponse;

typedef struct {
    uint8_t fileHashBytes;
    char *fileHash;
} diff;

listMessageResponse *LIST(int clientSock, uint8_t *serverFileCount, char *rcvBuf) {
    int option = 1;

    if (send(clientSock, &option, sizeof(option), 0) != sizeof(option)) {
        printf("Number of bytes sent: %d\n", (int)sizeof(option));
        fatal_error("send() sent unexpected number of bytes");
    }

    uint8_t bytesReceived = recv(clientSock, serverFileCount, sizeof(uint8_t), 0);

    if (bytesReceived < 0)
        fatal_error("First recv() failed");
    else if (bytesReceived == 0)
        fatal_error("Connection closed by server.\n");

    uint32_t totalMessageSize = *serverFileCount * sizeof(listMessageResponse);

    if (rcvBuf != NULL) {
        free(rcvBuf);
    }

    rcvBuf = (char *)malloc(totalMessageSize);

    if (rcvBuf == NULL) {
        fatal_error("malloc() failed for rcvBuf");
    }
    
    memset(rcvBuf, 0, totalMessageSize);
    int totalBytesReceived = 0;

    while (totalBytesReceived < totalMessageSize) {
        bytesReceived = recv(clientSock, rcvBuf + totalBytesReceived, totalMessageSize - totalBytesReceived, 0);

        if (bytesReceived < 0)
            fatal_error("recv() for file names and hashes failed");
        else if (bytesReceived == 0)
            printf("No more bytes received. Ending recv() loop.\n");
            break;

        totalBytesReceived += bytesReceived;
    }
    
    listMessageResponse *serverFiles = (listMessageResponse *)malloc(totalMessageSize);

    if (serverFiles == NULL)
        fatal_error("malloc() failed for serverFiles");

    int offset = 0;
    // Deserialize each listMessageResponse
    for (int i = 0; i < *serverFileCount; i++) {
        listMessageResponse *response = &serverFiles[i];

        // Initialize the listMessageResponse structure to zero
        memset(response, 0, sizeof(listMessageResponse));

        // Deserialize fileNameBytes
        memcpy(&response->fileNameBytes, rcvBuf + offset, sizeof(uint8_t));
        offset += sizeof(uint8_t);

        // Deserialize fileName
        memcpy(response->fileName, rcvBuf + offset, response->fileNameBytes);
        response->fileName[response->fileNameBytes] = '\0';
        offset += RCVBUFSIZE;

        // Deserialize fileHashBytes
        memcpy(&response->fileHashBytes, rcvBuf + offset, sizeof(uint8_t));
        offset += sizeof(uint8_t);

        // Deserialize fileHash
        memcpy(response->fileHash, rcvBuf + offset, response->fileHashBytes);
        response->fileHash[response->fileHashBytes] = '\0';
        offset += RCVBUFSIZE;
    }

    free(rcvBuf);
    return serverFiles;
}

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

listMessageResponse* getFileNamesAndHashes(int *fileCount) {
    DIR *currentDir;
    struct dirent *entry;
    char filePath[1024];
    int capacity = 10; // Initial capacity for storing file info

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
    
    // Loop through each entry in the directory
    while ((entry = readdir(currentDir)) != NULL) {
        snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, entry->d_name);
        struct stat fileStat;
        if (stat(filePath, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
            // Double size if capacity is reached
            if (*fileCount >= capacity) {
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

            // Copy file name
            strncpy(fileInfos[*fileCount].fileName, entry->d_name, RCVBUFSIZE - 1);
            fileInfos[*fileCount].fileName[RCVBUFSIZE - 1] = '\0';
            fileInfos[*fileCount].fileNameBytes = (uint8_t)strlen(entry->d_name);
            printf("%s\n", fileInfos[*fileCount].fileName);

            // Calculate and copy SHA-256 hash
            char* sha256 = calculateSHA256(filePath);

            if (sha256 != NULL) {
                strncpy(fileInfos[*fileCount].fileHash, sha256, RCVBUFSIZE - 1);
                fileInfos[*fileCount].fileHash[RCVBUFSIZE - 1] = '\0';
                fileInfos[*fileCount].fileHashBytes = (uint8_t)strlen(sha256);
                printf("%s\n", fileInfos[*fileCount].fileHash);
                free(sha256);
            } else {
                fprintf(stderr, "Failed to calculate SHA256 for file: %s\n", entry->d_name);
                continue;
            }

            fileCount++;
        }
    }

    closedir(currentDir);
    return fileInfos; // Return array of FileInfo

}
/*
void DIFF(listMessageResponse *serverFiles, int serverFileCount, listMessageResponse **clientFiles, int *clientFileCount) {
    DIR *dir;
    struct dirent *ent;
    *clientFileCount = 0;

    if ((dir = opendir(DATA_DIR)) != NULL) {
        // Count the number of files
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) {
                (*clientFileCount)++;
            }
        }
        closedir(dir);
    } else {
        perror("opendir");
        return;
    }

    *clientFiles = (listMessageResponse *)malloc((*clientFileCount) * sizeof(listMessageResponse));
    if (*clientFiles == NULL) {
        fatal_error("malloc() failed for clientFiles");
    }

    if ((dir = opendir(DATA_DIR)) != NULL) {
        int index = 0;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) {
                listMessageResponse *response = &(*clientFiles)[index];
                memset(response, 0, sizeof(listMessageResponse));

                response->fileNameBytes = strlen(ent->d_name);
                strncpy(response->fileName, ent->d_name, response->fileNameBytes);
                response->fileName[response->fileNameBytes] = '\0';

                char filePath[RCVBUFSIZE];
                snprintf(filePath, sizeof(filePath), "%s/%s", DATA_DIR, ent->d_name);

                response->fileHashBytes = SHA256_DIGEST_LENGTH * 2;
                compute_file_sha256(filePath, response->fileHash);
                response->fileHash[response->fileHashBytes] = '\0';

                index++;
            }
        }
        closedir(dir);
    } else {
        perror("opendir");
        return;
    }

    printf("Files on both machines:\n");
    for (int i = 0; i < serverFileCount; i++) {
        for (int j = 0; j < *clientFileCount; j++) {
            if (strcmp(serverFiles[i].fileHash, (*clientFiles)[j].fileHash) == 0) {
                printf("File: %s\n", serverFiles[i].fileName);
            }
        }
    }

    printf("Files missing on the client:\n");
    for (int i = 0; i < serverFileCount; i++) {
        int found = 0;
        for (int j = 0; j < *clientFileCount; j++) {
            if (strcmp(serverFiles[i].fileHash, (*clientFiles)[j].fileHash) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            printf("File: %s\n", serverFiles[i].fileName);
        }
    }
}

void PULL();
*/

/* The main function */
int main(int argc, char *argv[])
{
    int clientSock;		    /* socket descriptor */
    int msgLen;
    struct sockaddr_in serv_addr;   /* The server address */
    struct sockaddr_in client_addr; /* The client address */

    char *listedFiles;

    char *sndBuf;	    /* Send Buffer */
    char *rcvBuf;	    /* Receive Buffer */

    int servPort = 20000;
    char *servIP = "127.0.0.1";

    uint8_t serverFileCount;
    uint8_t clientFileCount;

    listMessageResponse *serverFiles;
    listMessageResponse *clientFiles;
    diff *diffFiles;

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
                /*---------- LIST ----------*/
                serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);

                if (serverFiles == NULL || serverFileCount == 0) {
                    printf("LIST failed. Exiting...\n");
                    break;
                }

                // Print the received messages for demonstration
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
                    serverFiles = LIST(clientSock, &serverFileCount, rcvBuf);
                }

                break;
            case 3:
                /*---------- PULL ----------*/
                // Send the integer 1 to the server
                if (send(clientSock, &option, sizeof(option), 0) != sizeof(option))
                    fatal_error("send() sent unexpected number of bytes");
                break;
            case 4:
                /*---------- LEAVE ----------*/
                close(clientSock);
                // Free the allocated memory for each fileName and fileHash
                if (serverFileCount > 0 && serverFiles != NULL) {
                    for (int i = 0; i < serverFileCount; i++) {
                        free(serverFiles[i].fileName);
                        free(serverFiles[i].fileHash);
                    }
                    free(serverFiles);
                }
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

