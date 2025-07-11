#ifndef QUEUE_MANAGER_H
#define QUEUE_MANAGER_H

// Basit thread-safe queue yapısı ve thread pool
typedef struct task_node {
    void (*func)(void*);
    void* arg;
    struct task_node* next;
} task_node_t;

typedef struct {
    task_node_t* head;
    task_node_t* tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int size;
    int max_size;
} task_queue_t;

typedef struct {
    pthread_t* threads;
    int thread_count;
    task_queue_t* queue;
    int running;
} thread_pool_t;

void* queue_processor(void* arg);
void task_queue_init(task_queue_t* q, int max_size);
void task_queue_destroy(task_queue_t* q);
int task_queue_push(task_queue_t* q, void (*func)(void*), void* arg);
task_node_t* task_queue_pop(task_queue_t* q);
void* thread_pool_worker(void* arg);
void thread_pool_init(thread_pool_t* pool, int thread_count, int queue_max_size);
int thread_pool_submit(thread_pool_t* pool, void (*func)(void*), void* arg);
void thread_pool_destroy(thread_pool_t* pool);

#endif // QUEUE_MANAGER_H