---
title: Jarvis OJ guess-writeup
date: 2018-09-18 14:25:00
tags:
- CTF
categories:
- CTF
---

## 一、基础 ##

### 1.alarm函数 ###

alarm函数也称为闹钟函数，它可以**在进程中设置一个定时器，当定时器指定的时间到时，它向进程发送SIGALRM信号**。可以设置忽略或者不捕获此信号，如果**采用默认方式其动作是终止调用该alarm函数的进程**

引用#include <unistd.h>;
 
函数标准式：unsigned int alarm(unsigned int seconds);
 
功能与作用：alarm()函数的主要功能是设置信号传送闹钟，即用来设置信号SIGALRM在经过参数seconds秒数后发送给目前的进程。**如果未设置信号SIGALARM的处理函数，那么alarm()默认处理终止进程。**
 
函数返回值：**如果在seconds秒内再次调用了alarm函数设置了新的闹钟，则后面定时器的设置将覆盖前面的设置**，即之前设置的秒数被新的闹钟时间取代，此时后定义的alarm函数返回前一个定义的alarm函数剩余的时间；**当参数seconds为0时，之前设置的定时器闹钟将被取消**，且alarm(0)返回0。

参考链接：[linux定时器之alarm](https://blog.csdn.net/u010155023/article/details/51984602)

### 2.socket ###

建立网络通信连接至少要一对端口号(socket)。socket本质是编程接口(API)，对TCP/IP的封装，TCP/IP也要提供可供程序员做网络开发所用的接口，这就是Socket编程接口；**HTTP是轿车，提供了封装或者显示数据的具体形式；Socket是发动机，提供了网络通信的能力。**

Socket的英文原义是“孔”或“插座”。作为BSD UNIX的进程通信机制，取后一种意思。通常也称作"套接字"，**用于描述IP地址和端口，是一个通信链的句柄，可以用来实现不同虚拟机或不同计算机之间的通信**。

**在Internet上的主机一般运行了多个服务软件，同时提供几种服务。每种服务都打开一个Socket，并绑定到一个端口上，不同的端口对应于不同的服务。**Socket正如其英文原义那样，像一个多孔插座。一台主机犹如布满各种插座的房间，每个插座有一个编号，有的插座提供220伏交流电， 有的提供110伏交流电，有的则提供有线电视节目。 客户软件将插头插到不同编号的插座，就可以得到不同的服务。

![socket提供服务器与客户端的通信能力](/assets/img/guess_socket.jpg)


----------

#### 函数原型： ####
> int socket(int domain, int type, int protocol);

#### 参数说明： ####

- domain：协议域，又称协议族（family）。常用的协议族有AF_INET、AF_INET6、AF_LOCAL（或称AF_UNIX，Unix域Socket）等。协议族决定了socket的地址类型，在通信中必须采用对应的地址，如AF_INET决定了要用ipv4地址（32位的）与端口号（16位的）的组合、AF_UNIX决定了要用一个绝对路径名作为地址。

- type：指定Socket类型。常用的socket类型有SOCK_STREAM、SOCK_DGRAM等。
	- 流式Socket（SOCK_STREAM）是一种面向连接的Socket，针对于面向连接的TCP服务应用。
	- 数据报式Socket（SOCK_DGRAM）是一种无连接的Socket，对应于无连接的UDP服务应用。

- protocol：指定协议。常用协议有IPPROTO_TCP、IPPROTO_UDP、IPPROTO_STCP、IPPROTO_TIPC等，分别对应TCP传输协议、UDP传输协议、STCP传输协议、TIPC传输协议。

注意：type和protocol不可以随意组合，如SOCK_STREAM不可以跟IPPROTO_UDP组合。**当第三个参数为0时，会自动选择第二个参数类型对应的默认协议**。


#### 返回值： ####
如果**调用成功就返回新创建的套接字的描述符，如果失败就返回INVALID_SOCKET（Linux下失败返回-1）。套接字描述符是一个整数类型的值。每个进程的进程空间里都有一个套接字描述符表，该表中存放着套接字描述符和套接字数据结构的对应关系**。该表中有一个字段存放新创建的套接字的描述符，另一个字段存放套接字数据结构的地址，因此根据套接字描述符就可以找到其对应的套接字数据结构。
**每个进程在自己的进程空间里都有一个套接字描述符表但是套接字数据结构都是在操作系统的内核缓冲里**。

### 3.linux命令 ###

**(1)pidof**

linux下的pidof命令：找出进程名对应的进程号pid

- -s：仅返回一个进程号；
- -c：仅显示具有相同“root”目录的进程；
- -x：显示由脚本开启的进程；
- -o：指定不显示的进程ID。

类似于ps -aux | grep 进程名。当然pidof更加精准，grep xxx可能会把进程名为yyxxx的pid也找出来

**(2)nc**

nc命令是netcat命令的简称，都是用来设置路由器的。

他的用途有很多：
（1）实现任意TCP/UDP端口的侦听，nc可以作为server以TCP或UDP方式侦听指定端口
（2）端口的扫描，nc可以作为client发起TCP或UDP连接
（3）机器之间传输文件
（4）机器之间网络测速   

常用选项：

- -l：用于指定nc将处于侦听模式。指定该参数，则意味着nc被当作server，侦听并接受连接，而非向其它地址发起连接。
- -s：指定发送数据的源IP地址，适用于多网卡机 
- -u：指定nc使用UDP协议，默认为TCP
- -v：输出交互或出错信息，新手调试时尤为有用
- -w：超时秒数，后面跟数字 
- -z：表示zero，表示扫描时不发送任何数据

参数：

- 主机：指定主机的IP地址或主机名称；
- 端口号：可以是单个整数或者是一个范围。

参考链接：[nc命令用法举例](https://www.cnblogs.com/nmap/p/6148306.html)

## 二、题解思路 ##



## 三、题解脚本 ##