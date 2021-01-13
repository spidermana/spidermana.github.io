---
layout:     post
title:      "  「usercorn」嵌入式系统fuzz研究之AFL-UNICORN "
subtitle:   "New Research Here…… "
date:       2019-07-24 13:34:00
author:     "许大仙"
tags:
    - 跨构架
---

为了研究跨CPU构架的内存安全性检测问题，开始学习AFL-Unicorn、drmemory、unicorn的问题。

## Unicorn

### Introduction

**Unicorn** is a lightweight multi-platform, multi-architecture CPU emulator framework.Unicorn是一个跨平台、跨构架的轻型CPU仿真框架。

Unicorn engine基于QEMU实现，区别在于Unicorn仅仅关注对CPU operations的仿真，不像QEMU还处理计算机的其他部分(been designed & implemented especially for CPU emulation)。

起初，Unicorn重用了QEMU的CPU仿真模块作为他的核心，并应用了很多设计改变，因此QEMU所有可以仿真的指令，Unicorn都可以仿真，but beyond that we can do more & do better in many aspects。

### highlights

The section below highlights the areas where Unicorn shines.

- **Framework**: QEMU是一个仿真器，而不是framework。因而不可以基于QEMU构建自己的工具，而Unicorn不同。
- **Flexible**: 
  - QEMU无法仿真a chunk of raw binary code without any context: it <u>requires either a proper executable binary</u> (for example, a file in ELF format), <u>or a whole system image with a full OS inside</u>。
  - 然而, Unicorn仅仅针对CPU operations进行仿真,并且能够仿真raw code without context。
- **Instrumentation**: QEMU不支持动态检测，但使用Unicorn，您可以为从CPU执行到内存访问的各种事件注册自定义处理程序(handler)。此功能提供了在仿真下监视和分析代码所需的全部功能。
- **Thread-safe**: QEMU无法同时处理多个CPU。相比之下，Unicorn是作为一个框架设计和实现的，因此一个程序可以同时模拟multiple code of different kinds of CPU(不同类型CPU下的多个代码)。
- **Bindings**: QEMU does not have binding itself. But as a framework, Unicorn supports multiple bindings on top of the core written in C. This makes it easy to be adopted by developers. A rich list of efficient bindings - 4 languages have been supported in version 0.9。
- **Lightweight**: Unicorn比QEMU轻得多，因为我们剥离了所有不涉及CPU仿真的子系统。因此，Unicorn的尺寸和内存消耗不到QEMU的10倍。
- **Safety**: QEMU has a bad track of security record with a lot of vulnerabilities that can be exploited to break out of the guest. 历史表明，所有这些bugs都来自设备，BIOS，固件等子系统，但它们都不是来自CPU仿真器组件。因此，原则上Unicorn更安全，因为它具有更小的攻击面。

### Tutorial for Unicorn

#### (1)C语言教程

The following sample code presents how to <u>emulate 32-bit code of X86 in C language.</u>

```c++
 1 #include <unicorn/unicorn.h>
 2 
 3 // code to be emulated，现在要用unicorn仿真运行两条指令：INC ecx; DEC edx【ecx+1，edx-1】
 4 #define X86_CODE32 "\x41\x4a" // INC ecx; DEC edx
 5 
 6 // memory address where emulation starts ，指定仿真内存的起始点
 7 #define ADDRESS 0x1000000
 8 
 9 int main(int argc, char **argv, char **envp)
10 {
11   uc_engine *uc; //仿真引擎
12   uc_err err;
13   int r_ecx = 0x1234;     // ECX register，寄存器初始化值【32bits，4字节】
14   int r_edx = 0x7890;     // EDX register
15 
16   printf("Emulate i386 code\n");
17 
18   // Initialize emulator in X86-32bit mode
19   err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc); //初始化仿真器，为X86构架UC_ARCH_X86、32bitUC_MODE_32；通过&uc，得到初始化以后的引擎
20   if (err != UC_ERR_OK) {
21     printf("Failed on uc_open() with error returned: %u\n", err);
22     return -1;
23   }
24 
25   // map 2MB memory for this emulation
26   uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);//传入uc引擎，从ADDRESS=0x1000000起分配2M的内存。all permissions READ, WRITE and EXECUTE——UC_PROT_ALL
27 
28   // write machine code to be emulated to memory，将要仿真的两条指令写入刚刚分配的2M内存中.其中uc传入对应指定构架和平台的仿真引擎，ADDRESS为写入起始点，X86_CODE32写入指令code，最后为写入大小。
29   if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
30     printf("Failed to write emulation code to memory, quit!\n");
31     return -1;
32   }
33 
34   // initialize machine registers，初始化寄存器
35   uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
36   uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
37 
38   // emulate code in infinite time & unlimited instructions，开始仿真code，其中“0, 0”设置无限时间和不限指令
39   err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
40   if (err) {
41     printf("Failed on uc_emu_start() with error returned %u: %s\n",
42       err, uc_strerror(err));
43   }
44 
45   // now print out some registers
46   printf("Emulation done. Below is the CPU context\n");
47 
48   uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);//读取运行code以后的寄存器值
49   uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
50   printf(">>> ECX = 0x%x\n", r_ecx);
51   printf(">>> EDX = 0x%x\n", r_edx);
52 
53   uc_close(uc);
54 
55   return 0;
56 }
```

##### 1.API总结：

初始化模拟器，指定构架和平台：uc_open(UC_ARCH_X86, UC_MODE_32, &uc);

- 参数一：平台
- 参数二：x位机器
- 参数三：模拟引擎【引用传参，此后复用】

为此次模拟分配内存：uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

- 参数一：模拟引擎
- 参数二：起始内存分配地址【虚拟地址】
- 参数三：分配大小
- 参数四：指定权限，RWX全开：UC_PROT_ALL

在指定内存中写入机器指令：uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1);

- 参数一：模拟引擎
- 参数二：起始内存地址
- 参数三：Raw binary code，code具体内容【机器码形式】
- 参数四：size

写寄存器：uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);

- 参数一：模拟引擎
- 参数二：寄存器宏定义
- 参数三：value【如果是64为机器，推荐使用 uint64_t】

开始仿真：uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);

- 参数一：模拟引擎
- 参数二：仿真运行的起始内存地址
- 参数三：终止地址
- 参数四：0，即无限时间infinite time
- 参数五：0，即unlimited instructions

读取寄存器：uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);

- 参数一：模拟引擎
- 参数二：寄存器宏定义
- 参数三：读取后存放位置

完成仿真：uc_close(uc);

#### (2)python教程

类似，仅仅是构建了引擎类`mu = Uc(UC_ARCH_X86, UC_MODE_32)`，再使用类成员函数mu.mem_map、mu.mem_write。

## Dr.Memory







## usercorn

### Introduction

- 基于qemu-user的分析仿真框架
- 可以在不同的host kernel上跑任意的二进制文件
- 在每一条指令上记录整个系统的状态
- 一种可序列化的紧凑格式，能够倒带和重新执行
- 易扩展并构建自己的工具
- It's useful out of the box for debugging and dynamic analysis.【Debug foreign architecture and OS binaries. You don't need a MIPS box. You don't need qemu-user. You don't even need Linux.】
- With an arch-neutral powerful lua-based scripting language and debugger.

Usercorn 可以仿真16-bit DOS, 32-bit and 64-bit ARM/MIPS/x86/SPARC binaries for Linux, Darwin, BSD, DECREE, and even operating systems like Redux.

对x86_64 linux和DECREE 的支持最好。

Usercorn at a basic level is like qemu-user in that it can <u>load a userspace binary like ELF, MachO, etc</u> into a CPU emulator and <u>provide a syscall emulator interface.</u>

You can **hook instructions, basic blocks, syscalls, memory access...** 

Usercorn is being built as a framework around the Unicorn Engine. It's <u>not just a way to run a binary on the command line. It can be loaded as a library</u>(`NewUsercorn("binary").Run(args, env)` will run an arbitrary supported app). It allows hooking many things.

Usercorn is **much less mature** than qemu-user. It **supports around ~50/400 Posix syscalls** and is <u>missing many architecture-specific features</u>.

Some architectures **still need work on memory segmentation and thread-local storage**【仍然需要在内存分段和线程存储上做一些支持】

Usercorn supports x86_64 best, and has various levels of support for ARM, MIPS, sparc, and m68k.

It's still very much WIP, but can **run many binaries at this point, even Linux binaries dynamically linked to glibc.**

Host support is best on OS X and Linux. 

Guest support is best on Linux.

### Install

- 具备go 1.6以上的环境

  - 如果使用apt-get，要配置GOPATH和PATH
  - https://blog.csdn.net/qq_41527782/article/details/83412078

- make deps，由于curl 会出现handshack fail等一系列问题，因此要修改makefile文件，先去下载一些tar.gz包，构建usercorn/go_pack中

  ```makefile
  # figure out if we can download Go
  GOVERSION=1.10.8
  ifeq "$(ARCH)" "x86_64"
  	ifeq "$(OS)" "Darwin"
  		GOURL = "go_back/go$(GOVERSION).darwin-amd64.tar.gz"  #提前下载好4个tar.gz
  	else ifeq "$(OS)" "Linux"
  		GOURL = "go_pack/go$(GOVERSION).linux-amd64.tar.gz"
  	endif
  endif
  ifeq "$(ARCH)" "i686"
  	ifeq "$(OS)" "Linux"
  		GOURL = "go_pack/go$(GOVERSION).linux-386.tar.gz"
  	endif
  endif
  ifneq (,$(filter $(ARCH),armv6l armv7l armv8l))
  	ifeq "$(OS)" "Linux"
  		GOURL = "go_pack/go$(GOVERSION).linux-armv6l.tar.gz"
  	endif
  endif
  
  ifeq ($(GOURL),)
  	GOMSG = "Go 1.6 or later is required. Visit https://golang.org/dl/ to download."
  else
  	GODIR = go-$(ARCH)-$(OS)
  endif
  
  deps/$(GODIR):
  	echo $(GOMSG)
  	[ -n $(GOURL) ] && \
  	mkdir -p deps/build deps/gopath && \
  	cd deps/build && \
  	mv ../../$(GOURL) go-dist.tar.gz&& \ #将curl，修改为mv，进行重命名
  	cd .. && tar -xf build/go-dist.tar.gz && \
  	mv go $(GODIR)
  ```

- make：make 的过程中可能会出现一些错误，主要是被墙的原因，因此一些golang的第三方库，需要在github上找到对应进行下载，并放置到go/src中

### Learning

1.usercorn run -ex 可以查看更多命令

- -trace -disbytes：查看字节

2.引入github上的package到go中

- https://blog.csdn.net/sinat_28545681/article/details/52535720
- 配置好GOROOT和GOPATH
- 输入go get github地址项目A，此后会自动下载项目到GOPATH中的src目录下
- 进入对应项目A的下载目录，然后 go build 编译，go install 安装

#### 1.structure

- usercorn/go/usercorn.go：对命令行的选项进行操作，二进制文件加载，hook，trace处理
- go/cmd/launcher.go：运行usercorn时，打印出来的helper用法提示。
- go/models/config.go：对trace以及系统全局选项/设置进行了操作和设置
- `arch`模块：在go/arch/构架/arch.go中初始化了构架，包括存储了汇编指令，构架信息，机器位数，寄存器组名称和宏，PC寄存器，SP寄存器等
  - 此后用u models.Usercorn，u.Arch()获取arch结构体中的字段，例如u.Arch().Dis
- 核心模块`models`：
  - models/trace/trace.go：trace相关的API在此实现，根据-trace选项，进行trace的操作，具体有Attach开启trace，Detach关闭trace等
    - regs：在go/arch/arm、arm64、mips、x86等文件夹下的arch.go定义各个构架的寄存器宏和PC
  - models/debug.go：Disas调用capstone进行了对机器码的反汇编，形成指令【返回指令集合和nil】。
    - 该函数被go/task.go中的Dis()调用。Dis()通过MemRead，从指定addr开启读取内存页，存储到p数组中，返回到mem，再调用Disas(mem,...)对mem中的机器码进行反汇编，从而返回汇编指令。
  - models/trace/ops.go：定义了操作类型的宏，jmp指令，内存读指令，系统调用指令类型等

trace启动调用链：go/cmd/main/main.go-> func main()  -> cmd.Main() ->  go/cmd/laucher.go中的Main()-> [输入usercorn之后的终端打印，并append args，cmd.main(args)，该main在Register中注册为Main]->go/cmd/cfg/main.go -> func Main(args []string) - > usercorn.go中的Run() -> u.trace.Attach()



## AFL-UNICORN

### Introduction

目的：仿真部分代码的执行并进行fuzz。并且仍然能够获得the coverage-based advantages of AFL。

例子：

For example, maybe you want to fuzz a parsing function from an embedded system that receives input via RF and isn’t easily debugged. 

Maybe the code you’re interested in is buried deep within a complex, slow program that you can’t easily fuzz through any traditional tools。

因而构建了Unicorn Mode的AFL——afl-unicorn，如果你能在Unicorn Engine中仿真你的code，那么你就可以使用afl-unicorn进行fuzz。

## 参考连接

- afl-unicorn仓库：https://github.com/Battelle/afl-unicorn
  
  - [how to install it, and how to use it](https://medium.com/hackernoon/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf)
  
- Unicorn——a multi-platform, multi-architecture CPU emulator framework:https://www.unicorn-engine.org/
  - [Tutorial for Unicorn](https://www.unicorn-engine.org/docs/tutorial.html)
  - NOTE: 可在 [Avatao website](https://platform.avatao.com/paths/8e720072-9169-4d4c-9569-c330ce7fd947)中找到更多教程【三个challenges】
  
- process-basics：https://www.helpwithpcs.com/hardware/processor-basics.php

- Usercorn：https://github.com/lunixbochs/usercorn

  - intro：https://news.ycombinator.com/item?id=11437962
  - [go支持,API 汇总](https://godoc.org/github.com/lunixbochs/usercorn/go#NewUsercorn)
  - [some API examples](https://golang.hotexamples.com/examples/github.com.lunixbochs.usercorn.go.models/Usercorn/RunShellcodeMapped/golang-usercorn-runshellcodemapped-method-examples.html)
  - [Usercorn 全局同步](https://sourcegraph.com/github.com/lunixbochs/usercorn/-/tree/go)
  - [linux上利用qemu运行跨构架程序](http://blog.eonew.cn/archives/454)
  

## 补充知识

#### ARM SVC

```assembly
28:     13c54:   e3a07005    mov r7, #5  ; 0x5   
  #在arch/arm/include/asm/unistd.h中：
  #define __NR_open  (__NR_SYSCALL_BASE+5)
  #其中，__NR_OABI_SYSCALL_BASE是0
  29:     
13c58: ef000000 svc 0x00000000 #产生软中断
  30:     13c5c:   e1a0700c    mov r7, ip
  31:     13c60:   e3700a01    cmn r0, #4096   ; 0x1000
  32:     13c64:   312fff1e    bxcc    lr
  33:     13c68:   ea0008d4    b   15fc0 <__syscall_error>
  34:  ......
```

通过上面的代码注释，可以看到，系统调用sys_open的系统调用号是5，**将系统调用号存放到寄存器R7当中，然后应用程序通过svc 0x00000000产生软中断，陷入内核空间。**

也许会好奇，ARM软中断不是用SWI吗，这里怎么变成了SVC了，请看下面一段话，是从ARM官网copy的：

>SVC
>
>超级用户调用。 
>语法
>
>SVC{cond} #immed
>
>其中：
>
>cond是一个可选的条件代码（请参阅条件执行）。 
>
>immed
>
>是一个表达式，其取值为以下范围内的一个整数：
>在 ARM 指令中为 0 到 224–1（24 位值）
>在 16 位 Thumb 指令中为 0-255（8 位值）。
>
>用法
>
>SVC 指令会引发一个异常。 这意味着处理器模式会更改为超级用户模式，CPSR 会保存到超级用户模式 SPSR，并且执行会跳转到 SVC 向量（请参阅《开发指南》中的第 6 章 处理处理器异常）。
>
>处理器会忽略 immed。 但异常处理程序会获取它，借以确定所请求的服务。 
>
>Note
>
>作为 ARM 汇编语言开发成果的一部分，SWI 指令已重命名为 SVC。 在此版本的 RVCT 中，SWI 指令反汇编为 SVC，并提供注释以指明这是以前的 SWI。 
>
>条件标记
>
>此指令不更改标记。 
>体系结构
>
>此 ARM 指令可用于所有版本的 ARM 体系结构。

#### ARM 和 thumb指令的区别

参考：https://blog.csdn.net/itismine/article/details/4753701

**ARM处理器有两种工作状态：ARM状态和Thumb状态。处理器可以在两种状态下随意切换。**

<u>处于ARM状态时，执行32位字对齐的ARM指令。</u>

<u>处于Thumb状态时，执行16位对齐的Thumb指令。</u>

ARM 和 Thumb 指令集的动态切换，是通过 BX 指令使用一个寄存器名作为参数来完成。 
程序控制权被转交给该寄存器中存储的地址 ( LSB 位被屏蔽 )。

如果 LSB=1, 则进入 Thumb 指令处理模式； 如果 LSB=0, 则进入 ARM 指令处理模式。

通俗点讲其实就是BX 跳转的地址最低位为1还是0来判断是进入Thumb指令处理模式还是进人ARM指令处理模式。



**Thumb 指令可以看作是 ARM 指令压缩形式的子集,**是针对代码密度的问题而提出的,它具有 16 位的代码密度但是它不如ARM指令的效率高。

Thumb 不是一个完整的体系结构,不能指望处理只执行Thumb 指令而不支持 ARM 指令集。因此,Thumb 指令只需要支持通用功能,必要时可以借助于完善的 ARM 指令集,比如,所有异常自动进入 ARM 状态。

在编写 Thumb 指令时,先要使用伪指令 CODE16 声明,而且在 ARM 指令中要使用 BX指令跳转到 Thumb 指令,以切换处理器状态.编写 ARM 指令时,则可使用伪指令 CODE32声明。

#### 调试 arm 程序

还需要安装一个 arm 的 gdb。

```shell
$ sudo apt install gdb-arm-none-eabi 
```

安装好后，执行下列命令开启远程调试

```shell
$ qemu-arm -g 1234 arm_helloworld
```

然后新开一个终端就可以了：

```shell
$ arm-none-eabi-gdb arm_helloworld
```

```shell
$ arm-linux-gnueabihf-objdump -M reg-names-special-atpcs -d test
```

#### qemu运行mips程序

##### qemu Invalid ELF image for this architecture

1.一方面可能是大小端或64or32bits没有匹配qemu的程序，例如qemu-mips或者qemu-mipsel

2.qemu不够新

[固件模拟调试环境搭建]([http://zeroisone.cc/2018/03/20/%E5%9B%BA%E4%BB%B6%E6%A8%A1%E6%8B%9F%E8%B0%83%E8%AF%95%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/](http://zeroisone.cc/2018/03/20/固件模拟调试环境搭建/))

在生成mips程序的时候，会为了简化程序size，加快执行，会stripped elf header，但是早期版本的qemu有需要获取header size等内容，因此会出现`/lib/ld.so.1: Invalid ELF image for this architecture`的问题。

但是最新的qemu已经成功patch了，因此需要install from source

**arm-gcc编译与链接参数mips-linux-gnu-gcc默认的编译方式是大端，可以在其后加上-EL来实现编译工具的小端编译，-EB大端编译，或者使用mipsel-linux-gnu-gcc**

mips-linux-gnu-ld也要加入-EL的参数

mips是big-endian的mips架构，

mipsel是little-endian的mips架构。

#### apt-cache search <pkg_name>

`apt-cache search pixman`找相关依赖包

#### arm-gcc交叉编译参数

- -marm (和-mthumb用来执行生成的代码在arm模式还是thumb模式执行)
- -mno-thumb-interwork （没有ARM/Thumb之间的切换）

#### thread-local-storage（TLS)

线程局部存储，英文为Thread Local Storage  ，缩写为TLS。

为什么要有TLS？原因在于，**全局变量与函数内定义的静态变量，是各个线程都可以访问的共享变量。**

<u>进程中的全局变量与函数内定义的静态(static)变量，是各个线程都可以访问的共享变量</u>。

**在一个线程修改的内存内容，对所有线程都生效。**这是一个优点也是一个缺点。

- 说它是优点，线程的数据交换变得非常快捷。
- 说它是缺点，一个线程死掉了，其它线程也性命不保; 多个线程访问共享数据，需要昂贵的同步开销，也容易造成同步相关的BUG。

为了避免同步问题，引入了TLS，即如果需要在一个线程内部的各个函数调用都能访问、但其它线程不能访问的变量（被称为static memory local to a thread 线程局部静态变量），就需要新的机制来实现。这就是TLS。

它主要是为了避免多个线程同时访存同一全局变量或者静态变量时所导致的冲突，尤其是多个线程同时需要修改这一变量时。为了解决这个问题，我们可以通过TLS机制，为每一个使用该全局变量的线程都提供一个变量值的副本，每一个线程均可以独立地改变自己的副本，而不会和其它线程的副本冲突。从线程的角度看，就好像每一个线程都完全拥有该变量。而从全局变量的角度上来看，就好像一个全局变量被克隆成了多份副本，而每一份副本都可以被一个线程独立地改变。

 线程局部存储在不同的平台有不同的实现，可移植性不太好。幸好要实现线程局部存储并不难，最简单的办法就是建立一个全局表，通过当前线程ID去查询相应的数据，因为各个线程的ID不同，查到的数据自然也不同了。

#### ld查找顺序

linux的可执行程序在执行的时候默认是先搜索/lib和/usr/lib这两个目录，然后按照/etc/ld.so.conf里面的配置搜索绝对路径。同时，Linux也提供了环境变量LDLIBRARYPATH供用户选择使用，用户可以通过设定它来查找除默认路径之外的其他路径，如查找/work/lib路径,你可以在/etc/rc.d/rc.local或其他系统启动后即可执行到的脚本添加如下语句：LDLIBRARYPATH =/work/lib:$(LDLIBRARYPATH)。并且LDLIBRARYPATH路径优先于系统默认路径之前查找（详细参考《使用LDLIBRARYPATH》）。

#### 查看使用的lib库

- 二进制文件为当前系统构架，则：ldd elf文件。
- 如果为非当前构架的二进制文件，则需要qemu环境，使用：`qemu-mipsel -E LD_TRACE_LOADED_OBJECTS=1 /lib/ld.so.1 ~/usercorn/tests/hello_mipsel`查看
  - 给定`qemu-<构架>`和`ld.so`文件

#### mips构架及汇编

mips架构通用寄存器命名

![mips架构通用寄存器命名](/assets/img/9927-27954-mipsjiagou-1.png)