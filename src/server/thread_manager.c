#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include "encrypted_client.h"
#include "thread_manager.h"
#include "logger.h"

void* listen_report_replies_thread(void* arg) {
    client_connection_t* conn = (client_connection_t*)arg;
    char buffer[4096];
    extern char jwt_token[];
    fd_set read_fds;
    struct timeval tv;
    int retries = 0;
    
    printf("[CLIENT][listen_report_replies_thread] Başlatıldı.\n");
    LOG_CLIENT_INFO("Report reply listener thread started");
    
    while (1) {
        // Set up the file descriptor set for select
        FD_ZERO(&read_fds);
        FD_SET(conn->socket, &read_fds);
        
        // Set timeout for 5 seconds
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        // Use select to wait for data with timeout
        int sel = select(conn->socket + 1, &read_fds, NULL, NULL, &tv);
        
        if (sel == -1) {
            LOG_CLIENT_ERROR("Select error in report reply listener thread");
            perror("[CLIENT][listen_report_replies_thread] select error");
            break;
        } 
        
        // Data is available
        ssize_t n = recv(conn->socket, buffer, sizeof(buffer)-1, 0);

        if (n > 0) {
            buffer[n] = '\0';
            printf("[CLIENT][listen_report_replies_thread] Mesaj alındı: %s\n", buffer);
            LOG_CLIENT_DEBUG("Received message in reply listener: %s", buffer);
            
            // Reset retry counter
            retries = 0;
            
            if (strncmp(buffer, "REPORT_REPLY:", 13) == 0) {
                char* p = buffer + 13;
                int report_id = atoi(p);
                char* msg = strchr(p, ':');
                if (msg) msg++;
                else msg = "";
                add_report_reply_thread(report_id, msg);
            }
        } else {
            LOG_CLIENT_ERROR("Error or connection closed in report reply listener: n=%zd", n);
            printf("[CLIENT][listen_report_replies_thread] recv döngüsü kırıldı. n=%zd\n", n);
            break;
        }
    }
    return NULL;
}

void add_report_reply_thread(int report_id, const char* msg) {
    pthread_mutex_lock(&report_reply_mutex);
    printf("[CLIENT][add_report_reply_thread] Çağrıldı: report_id=%d, msg=%s\n", report_id, msg);
    if (report_reply_count < MAX_REPORT_REPLIES) {
        report_replies[report_reply_count].report_id = report_id;
        strncpy(report_replies[report_reply_count].msg, msg, sizeof(report_replies[report_reply_count].msg)-1);
        report_replies[report_reply_count].msg[sizeof(report_replies[report_reply_count].msg)-1] = '\0';
        report_reply_count++;
        printf("[CLIENT][add_report_reply_thread] Eklendi. Toplam cevap: %d\n", report_reply_count);
    } else {
        printf("[CLIENT][add_report_reply_thread] HATA: MAX_REPORT_REPLIES aşıldı!\n");
    }
    pthread_mutex_unlock(&report_reply_mutex);
}