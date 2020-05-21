#include <nxt_application_kernel.h>
#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_port_memory_int.h>
#include <nxt_http.h>
#include <ak/ak_prepare.h>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#define PORT 8087

static nxt_application_kernel_t *nxt_application_kernel;

static nxt_int_t nxt_application_kernel_greet_controller(nxt_task_t *task,
                                                         nxt_port_t *controller_port);

//static void nxt_application_kernel_oosm_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

nxt_port_handlers_t nxt_application_kernel_process_port_handlers = {
    .quit = nxt_worker_process_quit_handler,
    .new_port = nxt_application_kernel_new_port_handler,
    .change_file = nxt_port_change_log_file_handler,
    .mmap = nxt_port_mmap_handler,
    //.data = nxt_application_kernel_data_handler,
    .remove_pid = nxt_port_remove_pid_handler,
    //.access_log   = nxt_router_access_log_reopen_handler,
    .rpc_ready = nxt_port_rpc_handler,
    .rpc_error = nxt_port_rpc_handler,
    //.oosm = nxt_application_kernel_oosm_handler,
};

static nxt_int_t run_AF_XDP_umem_server(nxt_task_t *task)
{
    //TODO: Check access
    nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: prepping the af_xdp umem env");

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int ret;
    struct xsk_umem_info_shared *umem;
    int ak_shm_fd, umem_shm_fd;

    //TODO: Hardcoded, this will change when AK provides an user interface
    int argc = 9;
    char *argv[] = {strdup("nxt_application_kernel"), strdup("-i"), strdup("eth0"), strdup("-q"), strdup("28"), strdup("-n"), strdup("3"), strdup("-r"), strdup("-N")};

    parse_command_line(argc, argv);

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: setrlimit(RLIMIT_MEMLOCK) %s", strerror(errno));
        return NXT_ERROR;
    }

    ak_shm_fd = AK_create_shared_memory_region();
    if (ak_shm_fd < 0)
    {
        nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: unable to create shared memory region");
        return NXT_ERROR;
    }

    umem_shm_fd = AK_create_umem_shared_memory_region(NUM_FRAMES * opt_xsk_frame_size);
    if (umem_shm_fd < 0)
    {
        nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: unable to create umem shared memory region");
        return NXT_ERROR;
    }

    umem = AK_create_umem_shared_memory(ak_shm_fd, umem_shm_fd, NUM_FRAMES * opt_xsk_frame_size, opt_mmap_flags);

    if (umem == NULL)
    {
        nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: umem is NULL");
        return NXT_ERROR;
    }

    umem_ptr = &umem;

    nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: umem configured");

    if (opt_bench == BENCH_RXDROP || opt_bench == BENCH_L2FWD)
    {
        ret = xsk_populate_fill_ring_shared(umem);
        if (ret < 0)
        {
            nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: populate umem fill rings failed");
            return NXT_ERROR;
        }

        nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: umem fill rings configured");
    }

    nxt_log(task, NXT_LOG_INFO, "APPLICATION_KERNEL: waiting to distribute umem fd %d", xsk_umem__fd(&umem->umem));

    ret = AK_socket_send_umem_fd(xsk_umem__fd(&umem->umem));

    if (ret < 0)
    {
        nxt_log(task, NXT_LOG_ERR, "APPLICATION_KERNEL: unable to send umem socket descriptor");
        return NXT_ERROR;
    }

    //TODO: Check code placement
    //TODO: Check AK exit flow to free resources

    //signal(SIGINT, int_exit_shared);
    //signal(SIGTERM, int_exit_shared);
    //signal(SIGABRT, int_exit_shared);

    return NXT_OK;
}

static nxt_int_t
nxt_application_kernel_greet_controller(nxt_task_t *task, nxt_port_t *controller_port)
{
    nxt_int_t ret;

    ret = nxt_port_socket_write(task, controller_port, NXT_PORT_MSG_PROCESS_READY,
                                -1, 0, 0, NULL);
    if (nxt_slow_path(ret != NXT_OK))
    {
        return NXT_ERROR;
    }    

    nxt_log(task, NXT_LOG_INFO, "Hello from application_kernel");    
    
    ret = run_AF_XDP_umem_server(task);    

    if (nxt_slow_path(ret != NXT_OK))
    {
        nxt_alert(task, "APPLICATION_KERNEL: Failed to launch umem server");
        return NXT_ERROR;
    }

    return NXT_OK;
}

void nxt_application_kernel_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->u.new_port != NULL && msg->u.new_port->type == NXT_PROCESS_CONTROLLER)
    {
        nxt_application_kernel_greet_controller(task, msg->u.new_port);
    }

    if (msg->port_msg.stream == 0)
    {
        return;
    }

    if (msg->u.new_port == NULL || msg->u.new_port->type != NXT_PROCESS_WORKER)
    {
        msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;
    }

    nxt_port_rpc_handler(task, msg);
}

void nxt_application_kernel_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    //TODO: Check code placement
}

nxt_int_t
nxt_application_kernel_start(nxt_task_t *task, void *data)
{
    nxt_int_t ret;
    nxt_port_t *controller_port;
    nxt_application_kernel_t *application_kernel;
    nxt_runtime_t *rt;

    rt = task->thread->runtime;

#if (NXT_TLS)
    rt->tls = nxt_service_get(rt->services, "SSL/TLS", "OpenSSL");
    if (nxt_slow_path(rt->tls == NULL))
    {
        return NXT_ERROR;
    }

    ret = rt->tls->library_init(task);
    if (nxt_slow_path(ret != NXT_OK))
    {
        return ret;
    }
#endif

    ret = nxt_http_init(task);
    if (nxt_slow_path(ret != NXT_OK))
    {
        return ret;
    }

    application_kernel = nxt_zalloc(sizeof(nxt_application_kernel_t));
    if (nxt_slow_path(application_kernel == NULL))
    {
        return NXT_ERROR;
    }

    nxt_queue_init(&application_kernel->engines);
    nxt_queue_init(&application_kernel->sockets);
    nxt_queue_init(&application_kernel->apps);

    nxt_application_kernel = application_kernel;

    controller_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];
    if (controller_port != NULL)
    {
        ret = nxt_application_kernel_greet_controller(task, controller_port);
        return ret;
    }

    return NXT_OK;
}