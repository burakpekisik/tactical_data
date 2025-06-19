#ifndef _P2P_CONNECTION_H_
#define _P2P_CONNECTION_H_

#include <time.h>
#include "connection_manager.h"

// P2P Node durumları
typedef enum {
    P2P_ROLE_NONE = 0,
    P2P_ROLE_BOOTSTRAP = 1,
    P2P_ROLE_PEER = 2,
    P2P_ROLE_RELAY = 3
} p2p_role_t;

// P2P Peer bilgisi
typedef struct {
    char ip[64];
    int port;
    char node_id[128];
    time_t last_seen;
    bool is_connected;
    int socket_fd;
} p2p_peer_t;

// P2P Node fonksiyonları
int p2p_node_init(connection_manager_t* manager);
int p2p_node_start(connection_manager_t* manager);
int p2p_node_stop(connection_manager_t* manager);
void* p2p_node_thread(void* arg);

// P2P Peer yönetimi
int p2p_add_peer(const char* ip, int port);
int p2p_remove_peer(const char* node_id);
int p2p_connect_to_peer(p2p_peer_t* peer);
int p2p_disconnect_from_peer(p2p_peer_t* peer);
void p2p_handle_peer_message(int socket, connection_manager_t* manager);

// P2P Protokol fonksiyonları
int p2p_send_discovery_message(void);
int p2p_send_keepalive(p2p_peer_t* peer);
int p2p_broadcast_message(const char* message);
int p2p_route_message(const char* target_node_id, const char* message);

// P2P Ağ fonksiyonları
int p2p_find_peers(void);
int p2p_join_network(const char* bootstrap_ip, int bootstrap_port);
int p2p_leave_network(void);
void p2p_maintain_connections(void);

// P2P İstatistik ve yönetim
void p2p_update_stats(connection_manager_t* manager);
void p2p_log_peer_activity(const char* node_id, const char* activity);
int p2p_get_peer_count(void);
void p2p_list_peers(void);

// P2P Peer thread wrapper
void* p2p_peer_thread_wrapper(void* arg);
int process_tactical_data(const char* data);
int process_p2p_tactical_data(const char* p2p_data);


#endif // _P2P_CONNECTION_H_
