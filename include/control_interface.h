#ifndef _CONTROL_INTERFACE_H_
#define _CONTROL_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

// Control interface fonksiyonları
int start_control_interface(void);
void stop_control_interface(void);
void* control_interface_thread(void* arg);
void handle_control_command(const char* command, int response_socket);

// Global control state
extern volatile int control_running;
extern pthread_t control_thread_id;

#endif // _CONTROL_INTERFACE_H_
