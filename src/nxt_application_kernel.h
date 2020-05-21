#include <nxt_main.h>
#include <nxt_main_process.h>

typedef struct nxt_http_request_s  nxt_http_request_t;
typedef struct nxt_http_action_s nxt_http_action_t;
typedef struct nxt_http_routes_s nxt_http_routes_t;
typedef struct nxt_application_kernel_access_log_s  nxt_application_kernel_access_log_t;

typedef struct {
    nxt_thread_spinlock_t    lock;
    nxt_queue_t              engines;

    nxt_queue_t              sockets;  /* of nxt_socket_conf_t */
    nxt_queue_t              apps;     /* of nxt_app_t */

    nxt_application_kernel_access_log_t  *access_log;
} nxt_application_kernel_t;

struct nxt_application_kernel_access_log_s {
    void                   (*handler)(nxt_task_t *task, nxt_http_request_t *r,
                                      nxt_application_kernel_access_log_t *access_log);
    nxt_fd_t               fd;
    nxt_str_t              path;
    uint32_t               count;
};

void nxt_application_kernel_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_application_kernel_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);