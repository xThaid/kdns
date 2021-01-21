#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <net/sock.h>

#include "dns.h"

#define PACKET_BUFFER_SIZE 1024

static struct socket *listen_sock;
static struct task_struct *kdnsd_thread;

static int udp_recvmsg(struct socket *sock, void *buf, size_t bufsiz, struct sockaddr_in *src) {
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = bufsiz};
    struct msghdr header = {.msg_name = src,
                         .msg_namelen = sizeof(struct sockaddr_in),
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &header, &iov, 1, bufsiz, 0);
}

static int udp_sendmsg(struct socket *sock, void *buf, size_t bufsiz, struct sockaddr_in *dst) {
    struct msghdr header = {.msg_name = dst,
                         .msg_namelen = sizeof(struct sockaddr_in),
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < bufsiz) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = bufsiz - done,
        };
        int length = kernel_sendmsg(sock, &header, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static int setsockopt(struct socket *sock, int level, int optname, int val) {
    return sock->ops->setsockopt(sock, level, optname, KERNEL_SOCKPTR(&val), sizeof(val));
}

static int open_listen_sock(struct socket **sock, int port) {
    int ret;
    struct sockaddr_in addr;

    ret = sock_create(AF_INET, SOCK_DGRAM, 0, sock);
    if (ret < 0) {
        pr_err("unable to create socket\n");
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    ret = kernel_bind(*sock, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        pr_err("unable to bind socket\n");
        goto err;
    }
    return 0;

    ret = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (ret < 0)
        goto err_setsockopt;
    
    ret = setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, 1);
    if (ret < 0)
        goto err_setsockopt;

err_setsockopt:
    pr_err("setsockopt failed\n");
err:
    sock_release(*sock);
    return ret;
}

static void close_listen_sock(struct socket *sock) {
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);
}

static int kdns_daemon(void *arg) {
    struct sockaddr_in addr;

    char *recv_buf = kmalloc(PACKET_BUFFER_SIZE, GFP_KERNEL);
    char *resp_buf = kmalloc(PACKET_BUFFER_SIZE, GFP_KERNEL);

    while (!kthread_should_stop()) {
        int reqsize, respsize;

        reqsize = udp_recvmsg(listen_sock, recv_buf, PACKET_BUFFER_SIZE, &addr);
        if (reqsize <= 0) {
            pr_err("recv error %d\n", reqsize);
            break;
        }
        pr_info("received msg len=%d\n", reqsize);

        respsize = kdns_query(recv_buf, reqsize, resp_buf);

        udp_sendmsg(listen_sock, resp_buf, respsize, &addr);
    }

    kfree(recv_buf);
    kfree(resp_buf);
    return 0;
}

static int __init mod_init(void){
    int ret;

    ret = kdns_init_db();
    if (ret < 0)
        return ret;

    ret = open_listen_sock(&listen_sock, DNS_SERVER_PORT);
    if (ret < 0)
        return ret;

    kdnsd_thread = kthread_run(kdns_daemon, NULL, "kdnsd");

    pr_info("kdns module loaded successfully\n");
    return 0;
}

static void __exit mod_exit(void){
    send_sig(SIGTERM, kdnsd_thread, 1);
    kthread_stop(kdnsd_thread);
    close_listen_sock(listen_sock);
    kdns_destroy_db();
    pr_info("kdns module unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jakub Urbańczyk");
MODULE_DESCRIPTION("kdns - a simple DNS server running as the kernel module");
MODULE_VERSION("1.0.0");