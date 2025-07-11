#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

void* listen_report_replies_thread(void* arg);
void add_report_reply_thread(int report_id, const char* msg);

#endif // THREAD_MANAGER_H