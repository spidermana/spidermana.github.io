---
title: ROPgadget工具
date: 2018-08-09 15:38:00
tags:
- CTF
categories:
- CTF
---


ROP的全称为Return-oriented programming（返回导向编程），这是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）。

## 一、linux _64与linux _86的区别 ##

linux_64与linux_86的区别主要有两点：

- 首先是**内存地址的范围由32位变成了64位**。但是**可以使用的内存地址不能大于0x00007fffffffffff，否则会抛出异常**。
- 其次是**函数参数的传递方式发生了改变**，x86中参数都是保存在栈上,但在x64中的前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9中，如果还有更多的参数的话才会保存在栈上。

由于参数不能直接溢出放在栈中，而是要存储在寄存器，那么就需要搜索有用的指令，用于设置参数比如pop %edi,mov %xxx,%esi等。

这时候ROPgadgets开源工具就派上用场了，它可以用于**搜索你所需要的rop链**。官方的说法是：This tool **lets you search your gadgets on your binaries** to facilitate your ROP exploitation.【就好像objdump -d test.out | grep pop 这样，但是ROPgadgets能搜索的节更多，用途更广更便捷】

## 二、linux安装 ROPgadget及官方用法 ##

    git clone https://github.com/JonathanSalwan/ROPgadget
    cd ROPgadget
    sudo python setup.py install
 
### Install ###

----------
**If you want to use ROPgadget, you have to install Capstone first.**

For the Capstone's installation on nix machine:

> $ pip install capstone 或者 sudo pip install capstone

已安装过会提示：Requirement already satisfied: capstone in ./.local/lib/python2.7/site-packages (3.0.5)

**Capstone supports multi-platforms (windows, ios, android, cygwin...)**. For the cross-compilation, please refer to the
[https://github.com/aquynh/capstone/blob/master/COMPILE.TXT ](https://github.com/aquynh/capstone/blob/master/COMPILE.TXT) file.

**After Capstone is installed, ROPgadget can be used as a standalone tool:**

> $ ROPgadget.py

**Or installed into the Python site-packages library, and executed from $PATH.**

> $ python setup.py install
> $ ROPgadget

Or installed from PyPi

> $ pip install ropgadget
> $ ROPgadget

### Usage ###

----------
    usage: ROPgadget.py [-h] [-v] [-c] [--binary <binary>] [--opcode <opcodes>]
					    [--string <string>] [--memstr <string>] [--depth <nbyte>]
					    [--only <key>] [--filter <key>] [--range <start-end>]
					    [--badbytes <byte>] [--rawArch <arch>] [--rawMode <mode>]
					    [--re <re>] [--offset <hexaddr>] [--ropchain] [--thumb]
					    [--console] [--norop] [--nojop] [--nosys] [--multibr]
					    [--all] [--dump]
    
    optional arguments:
		    -h, --help   show this help message and exit
		    -v, --versionDisplay the ROPgadget's version
		    -c, --checkUpdateChecks if a new version is available
		    --binary <binary>Specify a binary filename to analyze
		    --opcode <opcodes>   Search opcode in executable segment
		    --string <string>Search string in readable segment  #！！！！
		    --memstr <string>Search each byte in all readable segment   #！！！！
		    --depth <nbyte>  Depth for search engine (default 10)
		    --only <key> Only show specific instructions  #！！！用“xxx | yyy”显示多个满足要求的
		    --filter <key>   Suppress specific instructions
		    --range <start-end>  Search between two addresses (0x...-0x...)
		    --badbytes <byte>Rejects specific bytes in the gadget's address
		    --rawArch <arch> Specify an arch for a raw file
		    --rawMode <mode> Specify a mode for a raw file
		    --re <re>Regular expression
		    --offset <hexaddr>   Specify an offset for gadget addresses
		    --ropchain   Enable the ROP chain generation
		    --thumb  Use the thumb mode for the search engine (ARM only)
		    --consoleUse an interactive console for search engine
		    --norop  Disable ROP search engine
		    --nojop  Disable JOP search engine
		    --callPreceded   Only show gadgets which are call-preceded (x86 only)
		    --nosys  Disable SYS search engine
		    --multibrEnable multiple branch gadgets
		    --allDisables the removal of duplicate gadgets
		    --dump   Outputs the gadget bytes

## 三、ROPgadget示例 ##


> ~$ ROPgadget --binary test.out --only "pop|ret"
    
    Gadgets information
    ============================================================
    0x00000000004008ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    0x00000000004008ae : pop r13 ; pop r14 ; pop r15 ; ret
    0x00000000004008b0 : pop r14 ; pop r15 ; ret
    0x00000000004008b2 : pop r15 ; ret
    0x00000000004008ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    0x00000000004008af : pop rbp ; pop r14 ; pop r15 ; ret
    0x0000000000400700 : pop rbp ; ret
    0x00000000004008b3 : pop rdi ; ret
    0x00000000004008b1 : pop rsi ; pop r15 ; ret
    0x00000000004008ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
    0x0000000000400601 : ret
    0x0000000000400682 : ret 0x2009

跳转到0x00000000004008b3地址，就可以设置第一个函数参数，再ret到要去的函数。

## 阅读一下链接 ##

一、[一步一步学ROP之linux_x86篇](http://jaq.alibaba.com/community/art/show?spm=a313e.7916646.24000001.11.MtR4jX&articleid=403)

笔记：

> gcc -fno-stack-protector -z execstack -o level1 level1.c

这个命令编译程序。**-fno-stack-protector和-z execstack这两个参数会分别关掉DEP[堆栈不可执行]和Stack Protector[栈保护]**。

![gdb调试目标程序，确定溢出点](/assets/img/abc0.jpg)

正常的思维是使用gdb调试目标程序，然后查看内存来确定shellcode的位置。但当你真的执行exp[exploit]的时候你会发现shellcode压根就不在这个地址上！这是为什么呢？原因是gdb的调试环境会影响buf在内存中的位置，虽然我们**关闭了ASLR，但这只能保证buf的地址在gdb的调试环境中不变，但当我们直接执行./level1的时候，buf的位置会固定在别的地址上**

最简单的方法就是开启core dump这个功能。

![开启core dump](/assets/img/abc1.jpg)

注意：第二行是设置产生core文件的存储路径，可以自行定义。

开启之后，当出现内存错误的时候，系统会生成一个core dump文件在tmp目录下。然后我们再用gdb查看这个core文件就可以获取到buf真正的地址了。

![gdb core文件](/assets/img/abc2.jpg)


- ./level1运行，段错误：产生core文件
- gdb 二进制文件 core文件
- 确定buffer首地址[shellcode要放置的位置，用于ret返回用]

因为溢出点是140个字节，再加上4个字节的ret地址，我们可以**计算出buffer的地址为$esp-144。通过gdb的命令 “x/10s $esp-144”，我们可以得到buf的地址为0xbffff290**。

OK，现在溢出点，shellcode和返回值地址都有了，可以开始写exp了。

**pwntools这个工具**，因为它可以非常方便的**做到本地调试和远程攻击的转换**。本地测试成功后只需要简单的修改一条语句就可以马上进行远程攻击。

![本地调试/远程攻击](/assets/img/abc3.jpg)

最终本地测试代码如下：

![最终code](/assets/img/abc4.jpg)

执行exp：

![执行](/assets/img/abc5.jpg)


接下来我们**把这个目标程序作为一个服务绑定到服务器的某个端口上，这里我们可以使用socat这个工具来完成**，命令如下：

> socat TCP4-LISTEN:10001,fork EXEC: ./level1

**随后这个程序的IO就被重定向到10001这个端口**上了，并且可以**使用 nc 127.0.0.1 10001来访问我们的目标程序服务**了。

因为现在**目标程序是跑在socat的环境中，exp脚本除了要把p = process('./level1')换成p = remote('127.0.0.1',10001) 之外，ret的地址还会发生改变。解决方法还是采用生成core dump的方案，然后用gdb调试core文件获取返回地址。然后我们就可以使用exp进行远程溢出啦**！

即在socat环境下，gdb level1 /../../core




二、[一步一步学ROP之linux_x64篇](https://www.2cto.com/kf/201611/563061.html)
或https://blog.csdn.net/zsj2102/article/details/78560300


其他参考链接：

[一步一步学ROP之gadgets和2free篇 – 蒸米](http://www.vuln.cn/6643)





