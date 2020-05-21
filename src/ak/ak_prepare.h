// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2018 Intel Corporation. */

//#include <asm/barrier.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
//#include <linux/compiler.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sys/un.h>

#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <bpf/bpf.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define MAX_SOCKS 4

#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64

#define DEBUG_HEXDUMP 0

typedef __u64 u64;
typedef __u32 u32;

enum benchmark_type
{
    BENCH_RXDROP = 0,
    BENCH_TXONLY = 1,
    BENCH_L2FWD = 2,
};

static enum benchmark_type opt_bench = BENCH_RXDROP;
static u32 opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_queue;
static int opt_poll;
static int opt_interval = 1;
static u32 opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static u32 opt_umem_flags;
static int opt_unaligned_chunks;
static int opt_mmap_flags;
static u32 opt_xdp_bind_flags;
static int opt_xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
static bool opt_need_wakeup = true;
static u32 opt_num_xsks = 1;
//static u32 prog_id;

struct xsk_umem_info_shared
{
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem umem;
    void *buffer; // TODO: refactor to remove this
};

//TODO: This will later change based on the number of dependent applications
const char *AK_share_name = "AK_shared_memory";
const char *umem_area_share_name = "AK_umem_shared_memory";
const int AK_share_size = 4096 * 4096;
struct xsk_umem_info_shared **umem_ptr = NULL;

/*static void AK_unmap_umem_shared_memory(struct xsk_umem_info_shared *umem)
{
    if (!umem)
    {
        munmap(umem->buffer, NUM_FRAMES * opt_xsk_frame_size);
        munmap(umem, sizeof(struct xsk_umem_info_shared));
    }
}

static void int_exit_shared(int sig)
{

    struct xsk_umem_info_shared *umem = *umem_ptr;
    if (!umem)
    {
        (void)xsk_umem__delete_shared(&umem->umem);
        AK_unmap_umem_shared_memory(umem);
    }

    shm_unlink(AK_share_name);
    shm_unlink(umem_area_share_name);

    exit(EXIT_SUCCESS);
}*/

/*
static void __exit_with_error(int error, const char *file, const char *func,
                              int line)
{
    fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error,
            strerror(error));
    remove_xdp_program();
    exit(EXIT_FAILURE);
}

#define exit_with_error(error) \
    __exit_with_error(error, __FILE__, __func__, __LINE__)
*/

static void __print_with_error(int error, const char *file, const char *func,
                               int line)
{
    fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func, line, error,
            strerror(error));
}

#define print_with_error(error) \
    __print_with_error(error, __FILE__, __func__, __LINE__)

static struct option long_options[] = {
    {"rxdrop", no_argument, 0, 'r'},
    {"txonly", no_argument, 0, 't'},
    {"l2fwd", no_argument, 0, 'l'},
    {"interface", required_argument, 0, 'i'},
    {"queue", required_argument, 0, 'q'},
    {"poll", no_argument, 0, 'p'},
    {"xdp-skb", no_argument, 0, 'S'},
    {"xdp-native", no_argument, 0, 'N'},
    {"interval", required_argument, 0, 'n'},
    {"zero-copy", no_argument, 0, 'z'},
    {"copy", no_argument, 0, 'c'},
    {"frame-size", required_argument, 0, 'f'},
    {"no-need-wakeup", no_argument, 0, 'm'},
    {"unaligned", no_argument, 0, 'u'},
    {"shared-umem", no_argument, 0, 'M'},
    {"force", no_argument, 0, 'F'},
    {0, 0, 0, 0}};

static void usage(const char *prog)
{
    const char *str =
        "  Usage: %s [OPTIONS]\n"
        "  Options:\n"
        "  -r, --rxdrop		Discard all incoming packets (default)\n"
        "  -t, --txonly		Only send packets\n"
        "  -l, --l2fwd		MAC swap L2 forwarding\n"
        "  -i, --interface=n	Run on interface n\n"
        "  -q, --queue=n	Use queue n (default 0)\n"
        "  -p, --poll		Use poll syscall\n"
        "  -S, --xdp-skb=n	Use XDP skb-mod\n"
        "  -N, --xdp-native=n	Enforce XDP native mode\n"
        "  -n, --interval=n	Specify statistics update interval (default 1 sec).\n"
        "  -z, --zero-copy      Force zero-copy mode.\n"
        "  -c, --copy           Force copy mode.\n"
        "  -m, --no-need-wakeup Turn off use of driver need wakeup flag.\n"
        "  -f, --frame-size=n   Set the frame size (must be a power of two in aligned mode, default is %d).\n"
        "  -u, --unaligned	Enable unaligned chunk placement\n"
        "  -M, --shared-umem	Enable XDP_SHARED_UMEM\n"
        "  -F, --force		Force loading the XDP prog\n"
        "\n";
    fprintf(stderr, str, prog, XSK_UMEM__DEFAULT_FRAME_SIZE);
    exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
    int option_index, c;

    opterr = 0;

    for (;;)
    {
        c = getopt_long(argc, argv, "Frtli:q:psSNn:czf:muM",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'r':
            opt_bench = BENCH_RXDROP;
            break;
        case 't':
            opt_bench = BENCH_TXONLY;
            break;
        case 'l':
            opt_bench = BENCH_L2FWD;
            break;
        case 'i':
            opt_if = optarg;
            break;
        case 'q':
            opt_queue = atoi(optarg);
            break;
        case 'p':
            opt_poll = 1;
            break;
        case 'S':
            opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
            opt_xdp_bind_flags |= XDP_COPY;
            break;
        case 'N':
            opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
            break;
        case 'n':
            opt_interval = atoi(optarg);
            break;
        case 'z':
            opt_xdp_bind_flags |= XDP_ZEROCOPY;
            break;
        case 'c':
            opt_xdp_bind_flags |= XDP_COPY;
            break;
        case 'u':
            opt_umem_flags |= XDP_UMEM_UNALIGNED_CHUNK_FLAG;
            opt_unaligned_chunks = 1;
            opt_mmap_flags = MAP_HUGETLB;
            break;
        case 'F':
            opt_xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        case 'f':
            opt_xsk_frame_size = atoi(optarg);
            break;
        case 'm':
            opt_need_wakeup = false;
            opt_xdp_bind_flags &= ~XDP_USE_NEED_WAKEUP;
            break;
        case 'M':
            opt_num_xsks = MAX_SOCKS;
            break;
        default:
            usage(basename(argv[0]));
        }
    }

    opt_ifindex = if_nametoindex(opt_if);
    if (!opt_ifindex)
    {
        fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
                opt_if);
        usage(basename(argv[0]));
    }

    if ((opt_xsk_frame_size & (opt_xsk_frame_size - 1)) &&
        !opt_unaligned_chunks)
    {
        fprintf(stderr, "--frame-size=%d is not a power of two\n",
                opt_xsk_frame_size);
        usage(basename(argv[0]));
    }
}

static struct xsk_umem_info_shared *
xsk_configure_umem_shared(int shm_fd, int umem_shm_fd, int umem_size,
                          int umem_mmap_flags)
{
    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = opt_xsk_frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = opt_umem_flags};

    struct xsk_umem_info_shared *umem = mmap(NULL, sizeof(struct xsk_umem_info_shared),
                                             PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (umem == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: umem creation failed\n");
        print_with_error(-errno);
    }

    // Reserve memory for the umem. Use hugepages if unaligned chunk mode
    umem->buffer = mmap(NULL, umem_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS | umem_mmap_flags,
                        umem_shm_fd, 0);
    if (umem->buffer == MAP_FAILED)
    {
        fprintf(stderr, "ERROR: umem buffer creation failed\n");
        print_with_error(-errno);
    }

    int ret = xsk_umem__create_shared(&umem->umem, umem->buffer, umem_size,
                                      &umem->fq, &umem->cq, &cfg);

    if (ret < 0)
    {
        fprintf(stderr, "ERROR: umem setup failed\n");
        print_with_error(ret);
    }

    return umem;
}

static int xsk_populate_fill_ring_shared(struct xsk_umem_info_shared *umem)
{
    int ret, i;
    u32 idx;

    ret = xsk_ring_prod__reserve(&umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        return -1;
    }
    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) =
            i * opt_xsk_frame_size;
    xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return 0;
}

static int AK_send_fds(int socket, int *fds, int n)
{
    struct msghdr message;
    struct iovec iov[1];
    struct cmsghdr *control_message = NULL;
    char ctrl_buf[CMSG_SPACE(sizeof(int) * n)];
    char data[1];

    memset(&message, 0, sizeof(struct msghdr));
    memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int) * n));

    // We are passing at least one byte of data so that recvmsg() will not return 0
    data[0] = ' ';
    iov[0].iov_base = data;
    iov[0].iov_len = sizeof(data);

    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * n);
    message.msg_control = ctrl_buf;

    control_message = CMSG_FIRSTHDR(&message);
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = CMSG_LEN(sizeof(int) * n);

    memcpy((int *)CMSG_DATA(control_message), fds, n * sizeof(int));

    return sendmsg(socket, &message, 0);
}

static int AK_create_shared_memory_region()
{
    int ak_shm_fd;
    ak_shm_fd = shm_open(AK_share_name, O_CREAT | O_RDWR, 0666);
    if (ak_shm_fd < 0)
    {
        fprintf(stderr, "ERROR: unable to create AK shared memory\n");
        return -1;
    }

    int ret;
    ret = ftruncate(ak_shm_fd, AK_share_size);
    if (ret < 0)
    {
        fprintf(stderr, "ERROR: unable to set AK shared memory size\n");
        print_with_error(-errno);
        return -errno;
    }

    return ak_shm_fd;
}

static int AK_create_umem_shared_memory_region(int size)
{
    int umem_shm_fd;
    umem_shm_fd = shm_open(umem_area_share_name, O_CREAT | O_RDWR, 0666);
    if (umem_shm_fd < 0)
    {
        fprintf(stderr, "ERROR: unable to create AK umem shared memory\n");
        return -1;
    }

    int ret;
    ret = ftruncate(umem_shm_fd, size);
    if (ret < 0)
    {
        fprintf(stderr, "ERROR: unable to set AK umem shared memory size\n");
        print_with_error(-errno);
        return -errno;
    }

    return umem_shm_fd;
}

static struct xsk_umem_info_shared *AK_create_umem_shared_memory(int ak_shm_fd, int umem_shm_fd, int umem_size,
                                                                 int umem_mmap_flags)
{
    return xsk_configure_umem_shared(ak_shm_fd, umem_shm_fd,
                                     umem_size,
                                     umem_mmap_flags);
}

static int AK_socket_send_umem_fd(int fd)
{
    struct sockaddr_un addr;
    int sock;
    int conn;
    int ret;

    //TODO: This will later change based on the number of dependent applications
    const char *AK_socket_path = "/AK_socket";

    int fds[1];
    fds[0] = fd;

    // Create a unix domain socket
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        print_with_error(-errno);
        return -errno;
    }
    // Bind it to a abstract address
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(&addr.sun_path[1], AK_socket_path);

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        print_with_error(-errno);
        return -errno;
    }

    fprintf(stdout, "umem fd waiting to be sent=%d\n", fds[0]);

    // Listen
    ret = listen(sock, 1);
    if (ret < 0)
    {
        print_with_error(-errno);
        return -errno;
    }

    // Just send the file descriptor to anyone who connects
    //TODO: Later co-relate requests
    for (;;)
    {
        fprintf(stdout, "wait on accept");
        conn = accept(sock, NULL, 0);
        if (conn < 0)
        {
            print_with_error(-errno);
            return -errno;
        }

        ret = AK_send_fds(conn, fds, 1);
        if (ret < 0)
        {
            print_with_error(-errno);
            return -errno;
        }

        fprintf(stdout, "Sent umem fd=%d\n", fds[0]);

        ret = close(conn);
        if (ret < 0)
        {
            print_with_error(-errno);
            return -errno;
        }
        //close(sock);
    }

    return 0;
}
