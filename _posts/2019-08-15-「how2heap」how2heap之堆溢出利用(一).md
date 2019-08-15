---
layout:     post
title:      "「how2heap」how2heap之堆溢出利用(一)"
subtitle:   "newbie的堆溢出利用之路开启啦！本章讲first_fit/fastbin_dup/fastbin_dup_into_stack/fastbin_dup_consolidate/unsafe_unlink"
date:       2019-08-15 10:16:00
header-img: "img/post-bg-re-vs-ng2.jpg"
author:     "许大仙"
catalog: true
tags:
    - CTF
typora-root-url: ..
---

堆溢出的学习之路必须从[how2heap](https://github.com/shellphish/how2heap)开始！

本章的关键点是讲述unlink的利用，其他几种由于简单，大概只会简述和摘录。

note：堆的学习一定要多debug——[pwndbg](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md)

你一定需要一些大佬对堆的基础讲解[Glibc内存管理-Ptmalloc2源码分析](http://paper.seebug.org/papers/Archive/refs/heap/glibc内存管理ptmalloc源代码分析.pdf)

## first_fit

这个程序并不展示如何攻击,而是展示glibc的一种分配规则.

glibc使用一种**first-fit**算法去选择一个free-chunk，如果存在一个free-chunk并且足够大的话,**malloc**会优先选取这个chunk，即：

- 会先选大小最合适的最小的chunk
- 会先选最先被malloc而且已经被free的chunk
- 试着把a=256，b=512字节，把a,b都free掉，然后malloc(250)，但是他依然是分配小的a，而不是大的b。

这种机制就可以在被利用于**use after free**(简称**uaf**)的情形中【UAF：顾名思义，free了以后你还用！->谁让你不置为NULL】

![firstfit1](/img/newposts/firstfit1.png)

## fastbin_dup

这个程序展示了一个利用fastbin进行的double-free攻击. 攻击比较简单.

#### 1.fast bins基础

ptmalloc 中在分配过程中 引入了 fast bins【为了快速分配小的内存块】，不大于 max_fast （32位默认值为 64B，64位默认为128B）的 chunk 被释放后，首先会被放到 fast bins 中，fast bins 中的 chunk 并不改变它的使用标志 P【标志前面的chunk是否空闲，fastbin中该位永远为1，表示前面物理相邻的chunk不为空，这样也就无法将它们合并，保持了小的chunk】，当需要给用户分配的 chunk 小于或等于 max_fast 时，ptmalloc 首先会在 fast bins 中查找相应的空闲块， 然后才会去查找bins中的空闲chunk。在某个特定的时候，ptmalloc会遍历fast bins中的chunk，将相邻的空闲 chunk 进行合并，并将合并后的 chunk 加入 unsorted bin 中，然后再将 usorted bin 里的 chunk 加入 bins 中。 

#### 2.max_fast

**32位系统中**，用户的请求在16bytes到64bytes会被分配到fastbin中【由于是32位下是16字节对齐，因此最小的chunk位16字节】；**64位系统中**，用户的请求在32bytes到128bytes会被分配到fastbin中【64位系统下是32字节对齐】。

#### 3.Chunk 格式 

ptmalloc 在给用户分配的空间的前后加上了一些控制信息，用这样的方法来记录分配的信息，以便完成分配和释放工作。

##### (1)inuse chunk的格式

一个使用中的 chunk（使用中，就是指还没有被 free 掉）在内存中的样子【不同bins大同小异】如图所示： 

![firstfit1](/img/newposts/fastbin_dup1.png)

###### 标志位P

chunk 的第二个域【size of chunk】的最低一位为 P，它表示前一个块是否在使用中，**P 为 0 则表示前一个 chunk 为空闲**，这时 chunk 的第一个域 prev_size 才有效，prev_size 表示前一个 chunk 的 size，程序可以使用这个值来找到前一个 chunk 的开始地址。当 P 为 1 时，表示前一个 chunk 正在使用中，prev_size无效，程序也就不可以得到前一个chunk的大小。不能对前一个chunk进行任何操作。**ptmalloc 分配的第一个块总是将 P 设为 1，以防止程序引用到不存在的区域。**

###### 标志位M

Chunk 的第二个域的倒数第二个位为 M，他表示当前 chunk 是从哪个内存区域获得的虚拟内存。M 为 1 表示该 chunk 是从 mmap 映射区域分配的【大概率这个chunk很大】，否则是从 heap 区域分配的。

###### 标志位A

Chunk 的第二个域倒数第三个位为 A，表示该 chunk 属于主分配区或者非主分配区，如果属于非主分配区，将该位置为 1，否则置为 0。 

###### 注意

由于32位是16B对齐，那么size的后三个bit肯定是000，故用作标志位。

因而pwndbg中size字段，例如是0x91，那么说明标志位是001【0x91=10010**001**】

##### (2)free chunk的格式

空闲 chunk 在内存中的结构如图所示： 

![firstfit1](/img/newposts/fastbin_dup2.png)

**当 chunk 空闲时，其 M 状态不存在，只有 AP 状态【没有所属area】**，原本是用户数据区的地方存储了四个指针【可能只有两个】，指针 fd 指向后一个空闲的 chunk，而 bk 指向前一个空闲的 chunk，ptmalloc 通过这两个指针将大小相近的 chunk 连成一个双向链表。

对于 **large bin 中的空闲 chunk，还有两个指针，fd_nextsize 和 bk_nextsize**，这<u>两个指针用于加快在 large bin 中查找最近匹配的空闲 chunk</u>。

不同的 chunk 链表又是通过 bins 或者 fastbins 来组织的。 

#### 4.回到正题——double free

##### （1）图解

该程序展示了利用fastbin进行的double-free攻击

![firstfit1](/img/newposts/fastbin_dup3.png)

通过上述double free使得我们得到了两个指向同一个chunk的指针。

**注**：这里如果连续free同一个堆块（会有一个检查，用来防止double free的)，就会如下报错。

```c
Freeing the first one...
If we free 0x14a6010 again, things will crash because 0x14a6010 is at the top of the free list.
*** Error in `./fastbin_dup': double free or corruption (fasttop): 0x00000000014a6010 ***
Aborted (core dumped)
```

##### （2）pwndbg调试情况

![firstfit1](/img/newposts/fastbin_dup4.png)

![firstfit1](/img/newposts/fastbin_dup5.png)

![firstfit1](/img/newposts/fastbin_dup6.png)

这个时候fastbin就变成了【0x602000->0x602020->0x602000】，起始是一个循环指向。如果一直malloc(8)下去会依次按照0x602000、0x602020、0x602000、0x602020、0x602000、0x602020的顺序分配下去。

## fastbin_dup_into_stack



## fastbin_dup_consolidate

## unsafe_unlink