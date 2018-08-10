---
title: ROPgadgets工具
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
		    --string <string>Search string in readable segment
		    --memstr <string>Search each byte in all readable segment
		    --depth <nbyte>  Depth for search engine (default 10)
		    --only <key> Only show specific instructions
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

##  ##

https://blog.csdn.net/silence_stone/article/details/42964997

参考链接：

[一步一步学ROP之gadgets和2free篇 – 蒸米](http://www.vuln.cn/6643)

[一步一步学ROP之linux_x64篇](https://www.2cto.com/kf/201611/563061.html)

[一步一步学ROP之linux_x86篇](http://jaq.alibaba.com/community/art/show?spm=a313e.7916646.24000001.11.MtR4jX&articleid=403)