/* worker application */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>

uint32_t alphabet_count[26] = {0};
uint32_t alphabet_trans[26] = {0};

void count(char *filename, long start, long end) {
    FILE *fd = fopen(filename, "r");
    assert(fd != NULL);
    fseek(fd, start, SEEK_SET);
    char ch = fgetc(fd);
    while (ch != EOF && ftell(fd) != end) {
        if (isalpha(ch)) {
            ch = tolower(ch);
            alphabet_count[ch-'a']++;        
        }
        ch = fgetc(fd);
    }
    for (int i = 0; i < 26; ++i) 
        alphabet_trans[i] = htonl(alphabet_count[i]);
    fclose(fd);
}

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server;

    //Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket.\n");
    }
    printf("Socket created.\n");
     
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("10.0.0.1");
    server.sin_port = htons(12345);
 
    //Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }
    printf("Connected.\n");

    // receive message from master
    uint32_t *start = NULL, *end = NULL;
    char *file_path = NULL;
    int msg_len = 0;
    if((recv(sock, &msg_len, 4, 0)) < 0){
        printf("recv failed.\n");
        return -1;
    }
    msg_len = ntohl(msg_len);
    char *buffer = (char *)malloc(sizeof(char)*msg_len);
    if((recv(sock, buffer, msg_len, 0)) < 0){
        printf("recv failed.\n");
        return -1;
    }
    file_path = buffer+4;
    printf("recv file path: %s\n", file_path);
    start = (uint32_t *)(buffer+24);
    end   = (uint32_t *)(buffer+28);
    printf("start: %u\n", ntohl(*start));
    printf("end  : %u\n", ntohl(*end));

    count(file_path, (long)(ntohl(*start)), (long)(ntohl(*end)));

    if (send(sock, (char *)alphabet_trans, 104, 0) < 0) {
        printf("Send failed");
        return 1;
    }
    
    free(buffer);
    close(sock);
    return 0;
}
