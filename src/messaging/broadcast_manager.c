#include <stdio.h>
#include <stdlib.h>
#include "broadcast_manager.h"
#include "logger.h"
#include "chat_handler.h"
#include "chat_utils.h"
#include "chat_protocol.h"
#include "config.h"
#include "handle_manager.h"

extern server_chat_room_t server_rooms[MAX_CHAT_ROOMS];
extern int server_room_count;

// --- CHAT YAYIN (BROADCAST) ALTYAPISI ---
// Odaya socket ekle
void add_socket_to_room(int room_id, int client_socket) {
    for (int i = 0; i < server_room_count; i++) {
        if (server_rooms[i].room_id == room_id) {
            // Zaten ekli mi kontrol et
            for (int j = 0; j < server_rooms[i].participant_count; j++) {
                if (server_rooms[i].participant_sockets[j] == client_socket)
                    return;
            }
            if (server_rooms[i].participant_count < MAX_ROOM_PARTICIPANTS) {
                server_rooms[i].participant_sockets[server_rooms[i].participant_count++] = client_socket;
            }
            // Katılımcı listesini yazdır
            PRINTF_LOG("[ROOM %d] Katılımcı listesi (count=%d): ", room_id, server_rooms[i].participant_count);
            for (int k = 0; k < server_rooms[i].participant_count; k++) {
                printf("%d ", server_rooms[i].participant_sockets[k]);
            }
            printf("\n");
            return;
        }
    }
    // Oda yoksa ekle
    if (server_room_count < MAX_CHAT_ROOMS) {
        server_rooms[server_room_count].room_id = room_id;
        server_rooms[server_room_count].participant_sockets[0] = client_socket;
        server_rooms[server_room_count].participant_count = 1;
        server_room_count++;
        // Katılımcı listesini yazdır
        PRINTF_LOG("[ROOM %d] Katılımcı listesi (count=1): %d\n", room_id, client_socket);
    }
}

void broadcast_message_to_room(int room_id, const char* encrypted_response, int exclude_socket) {
    PRINTF_LOG("[BROADCAST] Room %d: Broadcasting to participants (excluding socket %d)\n", room_id, exclude_socket);
    int total_sent = 0;
    for (int i = 0; i < server_room_count; i++) {
        if (server_rooms[i].room_id == room_id) {
            PRINTF_LOG("[BROADCAST] Katılımcı listesi (count=%d): ", server_rooms[i].participant_count);
            for (int k = 0; k < server_rooms[i].participant_count; k++) {
                printf("%d ", server_rooms[i].participant_sockets[k]);
            }
            printf("\n");
            for (int j = 0; j < server_rooms[i].participant_count; j++) {
                int sock = server_rooms[i].participant_sockets[j];
                if (sock != exclude_socket) {
                    ssize_t sent = send(sock, encrypted_response, strlen(encrypted_response), 0);
                    PRINTF_LOG("[BROADCAST] Sent to socket %d, bytes: %zd, msg: %.40s...\n", sock, sent, encrypted_response);
                    if (sent < 0) {
                        perror("[BROADCAST] send() failed");
                    } else {
                        total_sent++;
                    }
                }
            }
            PRINTF_LOG("[BROADCAST] Toplam gönderilen katılımcı: %d\n", total_sent);
            break;
        }
    }
    // Oda yoksa hata ver
    if (total_sent == 0) {
        PRINTF_LOG("[BROADCAST] Oda bulunamadı veya katılımcı yok\n");
    }
}