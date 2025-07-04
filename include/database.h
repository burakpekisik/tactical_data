#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "chat_manager.h"

// Database connection structure
typedef struct {
    sqlite3 *db;
    char *db_path;
} db_connection_t;

// Unit structure
typedef struct {
    int id;
    char unit_id[50];
    char unit_name[100];
    char unit_type[50];
    char location[100];
    int active;
    char created_at[32];
} unit_t;

// Report structure
typedef struct {
    int id;
    int user_id;
    char status[50];
    double latitude;
    double longitude;
    char description[500];
    long timestamp;
    char created_at[32];
} report_t;

// Reply structure
typedef struct {
    int id;
    int user_id;
    int report_id;
    char message[500];
    long timestamp;
    char created_at[32];
} reply_t;

// Tactical Data Structure (matching data.json format)
typedef struct {
    char user_id[64];
    char status[64];
    double latitude;
    double longitude;
    char description[512];
    long timestamp;
    int is_valid;
    int report_id;
} tactical_data_t;

// Database functions
int db_init(const char *db_path);
int db_create_tables(void);
int db_close(void);

// Chat modülleri için yardımcı fonksiyonlar
int exec_sql_with_log(const char* sql, const char* success_log, const char* error_log);

// Unit operations
int db_insert_unit(const unit_t *unit);
int db_select_units(unit_t **units, int *count);
int db_update_unit(int id, const unit_t *unit);
int db_delete_unit(int id);
int db_get_unit_by_id(int id, unit_t *unit);

// Report operations
int db_insert_report(const report_t *report);
int db_select_reports(report_t **reports, int *count);
int db_select_reports_by_unit(int unit_id, report_t **reports, int *count);
int db_select_reports_by_user(int user_id, report_t **reports, int *count);
int db_update_report(int id, const report_t *report);
int db_delete_report(int id);
int db_get_report_by_id(int id, report_t *report);

// Reply operations
int db_select_replies_by_report(int report_id, reply_t **replies, int *count);
int db_select_replies_by_user(int user_id, reply_t **replies, int *count);
int db_select_replies_for_user_reports(int user_id, reply_t **replies, int *count);  // Yeni fonksiyon
int db_insert_reply(const reply_t *reply);

// Tactical data operations (JSON parse ve database insert)
int db_insert_tactical_data_from_json(const tactical_data_t *tactical_data);
int db_find_or_create_unit_by_id(const char* unit_id);
char* db_save_tactical_data_and_get_response(const tactical_data_t *tactical_data, const char* filename);

// USERS tablosu için fonksiyon prototipleri
int db_insert_user(int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege);
int db_select_user_by_id(int id, int *unit_id, char *username, char *name, char *surname, char *password, char *salt, int *privilege, char *created_at);
int db_select_user_by_username(const char *username, int *id, int *unit_id, char *name, char *surname, char *password, char *salt, int *privilege, char *created_at);
int db_update_user(int id, int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege);
int db_delete_user(int id);
int db_find_or_create_user_by_id(int id, int unit_id, const char* username, const char* name, const char* surname, const char* password, const char* salt, int privilege);
int db_find_or_create_user_by_username(const char* username, int unit_id, const char* name, const char* surname, const char* password, const char* salt, int privilege);
int register_user_with_argon2(int unit_id, const char* username, const char* name, const char* surname, const char* password);
char* login_user_with_argon2(const char *username, const char *password);

// Chat room operations
int db_insert_chat_room(const chat_room_t *room);
int db_select_chat_room_by_id(int room_id, chat_room_t* room);
int db_select_user_accessible_chat_rooms(const char* user_id, int user_privilege, 
                                        chat_room_t** rooms, int* count);
int db_update_chat_room(int room_id, const char* room_name, int room_type, 
                       const char* description, int current_users, 
                       const char* allowed_user_ids, int is_active);
int db_update_chat_room_users(int room_id, int current_users);
int db_update_chat_room_status(int room_id, int is_active);
int db_delete_chat_room(int room_id);
int db_delete_chat_room_hard(int room_id);

// Chat message operations
int db_insert_chat_message(int room_id, const char* sender_id, const char* sender_name, const char* content, 
                          const char* encrypted_content);
int db_select_chat_room_messages(int room_id, int limit, chat_message_t** messages, int* count);
int db_update_chat_message(int message_id, const char* content, int is_edited);
int db_delete_chat_message(int message_id);
int db_delete_chat_room_messages(int room_id);

int db_chat_get_latest_messages(int room_id, chat_message_t** messages, int* count, int limit);

// Utility functions
void db_free_units(unit_t *units, int count);
void db_free_reports(report_t *reports, int count);
void db_free_chat_rooms(chat_room_t *rooms, int count);
void db_free_chat_messages(chat_message_t *messages, int count);

// Test functions
int db_insert_test_data(void);

#endif // DATABASE_H
