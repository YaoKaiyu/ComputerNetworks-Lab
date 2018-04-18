/* master application */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <assert.h>

uint32_t alphabet_1[26] = {0};
uint32_t alphabet_2[26] = {0};

uint32_t get_file_size(const char *filename){  
    struct stat statbuf;  
    stat(filename, &statbuf);  
    return statbuf.st_size;  
} 
 
int main(int argc, const char *argv[])
{
    // Make sure we have an input string
    assert(argc == 2);

    // Read conf to get the address of these two clients
    char addr1[8] = {0}, addr2[8] = {0};
    FILE *readConf = fopen("./workers.conf", "r");
    assert(readConf != NULL);
    fscanf(readConf, "%s", addr1);
    fscanf(readConf, "%s", addr2);
    printf("Reading workers.conf is complete.\nadd1: %s\naddr2: %s\n", addr1, addr2);

    // Construct server and clients
    int s, cs1, cs2;
    struct sockaddr_in server, client1, client2;

    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
        return -1;
    }
    printf("Socket created.\n");
     
    // Prepare server's sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(12345);
    // Prepare clients' sockaddr_in structure
    client1.sin_family = AF_INET;
    client1.sin_addr.s_addr = inet_addr(addr1);
    client1.sin_port = htons(12345);
    client2.sin_family = AF_INET;
    client2.sin_addr.s_addr = inet_addr(addr2);
    client2.sin_port = htons(12345);
     
    // Bind
    if (bind(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Bind failed. Error");
        return -1;
    }
    printf("Bind done.\n");
     
    // Listen
    listen(s, 3);
     
    // Accept and incoming connection
    printf("Waiting for incoming connections...\n");
     
    // accept connection from Client 1 
    int c = sizeof(struct sockaddr_in);
    if ((cs1 = accept(s, (struct sockaddr *)&client1, (socklen_t *)&c)) < 0) {
        perror("accept failed: client 1");
        return 1;
    }
    printf("Client 1: Connection accepted.\n");

    // accept connection from Client 2
    if ((cs2 = accept(s, (struct sockaddr *)&client2, (socklen_t *)&c)) < 0) {
        perror("accept failed: client 2");
        return 1;
    }
    printf("Client 2: Connection accepted.\n");

    // Get information of the input file
    const char * txt_name = argv[1];
    uint32_t file_size = get_file_size(txt_name);

    // Assign separate jobs to these two clients
    // 1. get the file path
    char txt_path[20] = "./";
    strcat(txt_path, txt_name);

    // 2. get the parameters sent to workers
    char msg_1[32] = {0}, msg_2[32] = {0};
    uint32_t msg_len = htonl(32),
             start_1 = htonl(0), 
             end_1   = htonl(file_size/2),
             start_2 = htonl(file_size/2 + 1), 
             end_2   = htonl(file_size);
    // prepare message sent to client 1
    memcpy(msg_1, &msg_len, 4);
    memcpy(msg_1+4, txt_path, 20);
    memcpy(msg_1+24, &start_1, 4);
    memcpy(msg_1+28, &end_1, 4);
    // prepare message sent to client 2
    memcpy(msg_2, &msg_len, 4);
    memcpy(msg_2+4, txt_path, 20);
    memcpy(msg_2+24, &start_2, 4);
    memcpy(msg_2+28, &end_2, 4);

    // messages sent to client 1
    if (send(cs1, &msg_len, 4, 0) < 0) {
        printf("Send failed");
        return 1;
    }
    if (send(cs1, msg_1, 32, 0) < 0) {
        printf("Send failed");
        return 1;
    }
    // messages sent to client 2
    if (send(cs2, &msg_len, 4, 0) < 0) {
        printf("Send failed");
        return 1;
    }
    if (send(cs2, msg_2, 32, 0) < 0) {
        printf("Send failed");
        return 1;
    }    

    // message received from client 1
    if (recv(cs1, (char *)alphabet_1, 104, 0) < 0) {
        printf("recv failed\n");
        return 1;
    }
    // message received from client 2
    if (recv(cs2, (char *)alphabet_2, 104, 0) < 0) {
        printf("recv failed\n");
        return 1;
    }
    printf("recv done\n");

    for(int i = 0; i < 26; i++)
        printf("%c: %u\n", 'a'+i, ntohl(alphabet_1[i])+ntohl(alphabet_2[i]));

    close(s);
    fclose(readConf);
    return 0;
}
