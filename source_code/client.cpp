#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h> 

using namespace std;

int main() {
    int clientsocket;
    char message[1024];
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    cout << "Client start" << endl;
    clientsocket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8081);
    serverAddr.sin_addr.s_addr = inet_addr("xxx.xxx.xxx.xxx");
    cout << serverAddr.sin_addr.s_addr << endl;
    
    memset(serverAddr.sin_zero, '\0', sizeof(serverAddr.sin_zero));

    addr_size = sizeof(serverAddr);
    if(connect(clientsocket, (struct sockaddr *) &serverAddr, addr_size) < 0) {
        close(clientsocket);
        perror("connect failed");
        exit(EXIT_FAILURE);
    }
    cout << "Connected..." << endl;
    while(1) {
        memset(message, '\0', sizeof(message));
        cin.getline(message, 1024);
        
        if( send(clientsocket, message, strlen(message), 0) < 0) {
            cout << "Send Failed..." << endl;
        }else{
            cout << "Send Succes..." << endl;
            if(strcmp(message,"exit()") == 0) {
                cout << "Terminate client" << endl;
                break;
            }
        }

    }

    close(clientsocket);

    return 0;
}