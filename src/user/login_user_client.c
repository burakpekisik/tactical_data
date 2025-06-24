#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "login_user.h"
#include "config.h"

// Sunucuya bağlanıp kullanıcı adı ve şifre ile login olup JWT token döndürür
char* client_login_to_server(const char* username, const char* password) {
    int sockfd;
    struct sockaddr_in serv_addr;
    char sendbuf[256];
    char recvbuf[2048];
    int n;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return NULL;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(CONFIG_PORT); // Sunucu portu
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Gerekirse değiştirin

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return NULL;
    }

    snprintf(sendbuf, sizeof(sendbuf), "LOGIN:%s:%s", username, password);
    if (send(sockfd, sendbuf, strlen(sendbuf), 0) < 0) {
        perror("send");
        close(sockfd);
        return NULL;
    }

    n = recv(sockfd, recvbuf, sizeof(recvbuf)-1, 0);
    if (n <= 0) {
        close(sockfd);
        return NULL;
    }
    recvbuf[n] = '\0';
    close(sockfd);

    // Sunucu JWT token döndürüyorsa onu al
    if (strncmp(recvbuf, "JWT:", 4) == 0) {
        char* token = strdup(recvbuf + 4);
        return token;
    }
    return NULL;
}
