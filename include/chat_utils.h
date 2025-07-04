#ifndef CHAT_UTILS_H
#define CHAT_UTILS_H

#include "chat_manager.h"
#include <stdint.h>
#include <time.h>

// Utility fonksiyonları
char* format_timestamp(time_t timestamp);
char* format_chat_message_display(const char* sender_name, const char* message, time_t timestamp);
int validate_room_name(const char* room_name);
int validate_user_id_list(const char* user_id_list);

// Input validation
int is_valid_message(const char* message);

// Yardımcı fonksiyonlar (business logic)
int chat_db_is_user_allowed_in_room(const char* user_id, int user_privilege, 
                                   const chat_room_t* room);

// Memory management for chat room lists
void chat_room_list_free(chat_room_list_t* list);

#endif // CHAT_UTILS_H
