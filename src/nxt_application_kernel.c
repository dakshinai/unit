#include <nxt_application_kernel.h>
#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_port_memory_int.h>
#include <nxt_http.h>


#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8087 


static nxt_application_kernel_t  *nxt_application_kernel;

static void nxt_application_kernel_greet_controller(nxt_task_t *task,
    nxt_port_t *controller_port);

static void nxt_application_kernel_oosm_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

nxt_port_handlers_t  nxt_application_kernel_process_port_handlers = {
    .quit         = nxt_worker_process_quit_handler,
    .new_port     = nxt_application_kernel_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    //.data         = nxt_router_conf_data_handler,
    //.remove_pid   = nxt_router_remove_pid_handler,
    //.access_log   = nxt_router_access_log_reopen_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
    .oosm         = nxt_application_kernel_oosm_handler,
};


static void run_socket_file_server(nxt_task_t *task){

    //nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: run_socket_file_server"); 

    int server_fd, new_socket; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    char buffer[1024] = {0}; 
    const char *hello = "Hello from application_kernel server\n"; 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    {         
        nxt_log(task, NXT_LOG_ERR, "socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8087
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        nxt_log(task, NXT_LOG_ERR, "setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 
       
    // Forcefully attaching socket to the port 8087 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        nxt_log(task, NXT_LOG_ERR, "bind failed"); 
        exit(EXIT_FAILURE); 
    } 

    //nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: bind done"); 

    if (listen(server_fd, 3) < 0) 
    { 
        nxt_log(task, NXT_LOG_ERR, "listen"); 
        exit(EXIT_FAILURE); 
    } 

    //nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: listen done"); 

    while(1) {

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                        (socklen_t*)&addrlen))<0) 
        { 
            nxt_log(task, NXT_LOG_ERR, "accept"); 
            exit(EXIT_FAILURE); 
        } 
        //nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: accept done"); 

        read(new_socket , buffer, 1024); 
        nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: Received: %s", buffer); 

        send(new_socket , hello , strlen(hello) , 0 ); 
        nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: Sent: %s", hello); 

        close(new_socket);
        //nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: accept close");
    
    }
    
}

static void
nxt_application_kernel_greet_controller(nxt_task_t *task, nxt_port_t *controller_port)
{
    nxt_log(task, NXT_LOG_INFO, "Hello from application_kernel");
    run_socket_file_server(task);
    nxt_port_socket_write(task, controller_port, NXT_PORT_MSG_PROCESS_READY,
                          -1, 0, 0, NULL);
}

void
nxt_application_kernel_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->u.new_port != NULL
        && msg->u.new_port->type == NXT_PROCESS_CONTROLLER)
    {
        nxt_application_kernel_greet_controller(task, msg->u.new_port);
    }

    if (msg->port_msg.stream == 0) {
        return;
    }

    if (msg->u.new_port == NULL
        || msg->u.new_port->type != NXT_PROCESS_WORKER)
    {
        msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;
    }

    nxt_port_rpc_handler(task, msg);
}

static void
nxt_application_kernel_oosm_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t                   mi;
    uint32_t                 i;
    nxt_bool_t               ack;
    nxt_process_t            *process;
    nxt_free_map_t           *m;
    nxt_port_mmap_header_t   *hdr;

    nxt_debug(task, "oosm in %PI", msg->port_msg.pid);

    process = nxt_runtime_process_find(task->thread->runtime,
                                       msg->port_msg.pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    ack = 0;

    /*
     * To mitigate possible racing condition (when OOSM message received
     * after some of the memory was already freed), need to try to find
     * first free segment in shared memory and send ACK if found.
     */

    nxt_thread_mutex_lock(&process->incoming.mutex);

    for (i = 0; i < process->incoming.size; i++) {
        hdr = process->incoming.elts[i].mmap_handler->hdr;
        m = hdr->free_map;

        for (mi = 0; mi < MAX_FREE_IDX; mi++) {
            if (m[mi] != 0) {
                ack = 1;

                nxt_debug(task, "oosm: already free #%uD %uz = 0x%08xA",
                          i, mi, m[mi]);

                break;
            }
        }
    }

    nxt_thread_mutex_unlock(&process->incoming.mutex);

    if (ack) {
        (void) nxt_port_socket_write(task, msg->port, NXT_PORT_MSG_SHM_ACK,
                                     -1, 0, 0, NULL);
    }
}

nxt_int_t
nxt_application_kernel_start(nxt_task_t *task, void *data)
{
    nxt_int_t      ret;
    nxt_port_t     *controller_port;
    nxt_application_kernel_t   *application_kernel;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    //nxt_log(task, NXT_LOG_INFO, "In application kernel start fn1");

#if (NXT_TLS)
    rt->tls = nxt_service_get(rt->services, "SSL/TLS", "OpenSSL");
    if (nxt_slow_path(rt->tls == NULL)) {
        return NXT_ERROR;
    }

    ret = rt->tls->library_init(task);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }
#endif

    ret = nxt_http_init(task, rt);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    //nxt_log(task, NXT_LOG_INFO, "In application kernel start fn2");

    application_kernel = nxt_zalloc(sizeof(nxt_application_kernel_t));
    if (nxt_slow_path(application_kernel == NULL)) {
        return NXT_ERROR;
    }

    //nxt_log(task, NXT_LOG_INFO, "In application kernel start fn3");

    nxt_queue_init(&application_kernel->engines);
    nxt_queue_init(&application_kernel->sockets);
    nxt_queue_init(&application_kernel->apps);

    nxt_application_kernel = application_kernel;

    //nxt_log(task, NXT_LOG_INFO, "In application kernel start fn4");

    controller_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];
    if (controller_port != NULL) {
        nxt_application_kernel_greet_controller(task, controller_port);
    }

    //nxt_log(task, NXT_LOG_INFO, "In application kernel start fn5");

    return NXT_OK;
}