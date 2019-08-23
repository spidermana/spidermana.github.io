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

#### 攻击思路

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

[https://qrzbing.cn/2019/07/08/how2heap-2/#%E8%A7%A3%E9%87%8A](https://qrzbing.cn/2019/07/08/how2heap-2/#解释)

https://blog.csdn.net/qq_29343201/article/details/59477082

https://www.anquanke.com/post/id/86809

https://xz.aliyun.com/t/2582#toc-6