---
layout:     post
title:      "「how2heap」how2heap之堆溢出利用(一)"
subtitle:   "newbie的堆溢出利用之路开启啦！本章讲first_fit/fastbin_dup/_into_stack/_consolidate/unsafe_unlink"
date:       2019-08-15 10:16:00
header-img:   "img/post-bg-re-vs-ng2.jpg"
author:     "许大仙"
catalog: true
tags:
    - CTF
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

![firstfit1](/img/how2heap/firstfit1.png)

## fastbin_dup

这个程序展示了一个利用fastbin进行的double-free攻击. 攻击比较简单.

#### 1.fast bins基础

ptmalloc 中在分配过程中 引入了 fast bins【为了快速分配小的内存块】，不大于 max_fast （32位默认值为 64B，64位默认为128B）的 chunk 被释放后，首先会被放到 fast bins 中，fast bins 中的 chunk 并不改变它的使用标志 P【<u>标志前面的chunk是否空闲，fastbin中该位永远为1，表示前面物理相邻的chunk不为空，这样也就无法将它们合并，保持了小的chunk</u>】，当需要给用户分配的 chunk 小于或等于 max_fast 时，ptmalloc 首先会在 fast bins 中查找相应的空闲块， 然后才会去查找bins中的空闲chunk。在某个特定的时候，ptmalloc会遍历fast bins中的chunk，将相邻的空闲 chunk 进行合并，并将合并后的 chunk 加入 unsorted bin 中，然后再将 usorted bin 里的 chunk 加入 bins 中。 

#### 2.max_fast

**32位系统中**，用户的请求在16bytes到64bytes会被分配到fastbin中【由于是32位下是16字节对齐，因此最小的chunk位16字节】；**64位系统中**，用户的请求在32bytes到128bytes会被分配到fastbin中【64位系统下是32字节对齐】。

#### 3.Chunk 格式 

ptmalloc 在给用户分配的空间的前后加上了一些控制信息，用这样的方法来记录分配的信息，以便完成分配和释放工作。

##### (1)inuse chunk的格式及标志位PMA

一个使用中的 chunk（使用中，就是指还没有被 free 掉）在内存中的样子【不同bins大同小异】如图所示： 

![firstfit1](/img/how2heap/fastbin_dup1.png)

**标志位P**

chunk 的第二个域【size of chunk】的最低一位为 P，它表示前一个块是否在使用中，**P 为 0 则表示前一个 chunk 为空闲**，这时 chunk 的第一个域 prev_size 才有效，prev_size 表示前一个 chunk 的 size，程序可以使用这个值来找到前一个 chunk 的开始地址。当 P 为 1 时，表示前一个 chunk 正在使用中，prev_size无效，程序也就不可以得到前一个chunk的大小。不能对前一个chunk进行任何操作。**ptmalloc 分配的第一个块总是将 P 设为 1，以防止程序引用到不存在的区域。**

**标志位M**

Chunk 的第二个域的倒数第二个位为 M，他表示当前 chunk 是从哪个内存区域获得的虚拟内存。M 为 1 表示该 chunk 是从 mmap 映射区域分配的【大概率这个chunk很大】，否则是从 heap 区域分配的。

**标志位A**

Chunk 的第二个域倒数第三个位为 A，表示该 chunk 属于主分配区或者非主分配区，如果属于非主分配区，将该位置为 1，否则置为 0。 

**注意**

由于32位是16B对齐，那么size的后三个bit肯定是000，故用作标志位。

因而pwndbg中size字段，例如是0x91，那么说明标志位是001【0x91=10010**001**】

##### (2)free chunk的格式

空闲 chunk 在内存中的结构如图所示： 

![firstfit1](/img/how2heap/fastbin_dup2.png)

**当 chunk 空闲时，其 M 状态不存在，只有 AP 状态【没有所属area】**，原本是用户数据区的地方存储了四个指针【可能只有两个】，指针 fd 指向后一个空闲的 chunk，而 bk 指向前一个空闲的 chunk，ptmalloc 通过这两个指针将大小相近的 chunk 连成一个双向链表。

对于 **large bin 中的空闲 chunk，还有两个指针，fd_nextsize 和 bk_nextsize**，这<u>两个指针用于加快在 large bin 中查找最近匹配的空闲 chunk</u>。

不同的 chunk 链表又是通过 bins 或者 fastbins 来组织的。 

#### 4.回到正题——double free

##### （1）图解

该程序展示了利用fastbin进行的double-free攻击

![firstfit1](/img/how2heap/fastbin_dup3.png)

通过上述double free使得我们得到了两个指向同一个chunk的指针。

**注**：这里如果连续free同一个堆块（会有一个检查，用来防止double free的)，就会如下报错。

```c
Freeing the first one...
If we free 0x14a6010 again, things will crash because 0x14a6010 is at the top of the free list.
*** Error in `./fastbin_dup': double free or corruption (fasttop): 0x00000000014a6010 ***
Aborted (core dumped)
```

##### （2）pwndbg调试情况

![firstfit1](/img/how2heap/fastbin_dup4.png)

![firstfit2](/img/how2heap/fastbin_dup5.png)

![firstfit3](/img/how2heap/fastbin_dup6.png)

这个时候fastbin就变成了【0x602000->0x602020->0x602000】，起始是一个循环指向。如果一直malloc(8)下去会依次按照0x602000、0x602020、0x602000、0x602020、0x602000、0x602020的顺序分配下去。【由于fastbin要避免合并，因此标志位P一直保持1，即使前面的chunk已经free】

## fastbin_dup_into_stack

本案例是利用double free的漏洞，来构造一个假的堆块头，把指向下一个空闲块(free list)改成栈地址，这样就可以分配到一个栈地址，从而影响到栈上的数据。

#### 1.关键思路

本题的关键是明确，**bins中的每个bin【or list】是通过fd和bk进行链接的，也就是说如果我修改了fd或者bk，链表就会变化**，通过当前chunk找下一个chunk就是看当前chunk的fd，那么如果我可以控制一个chunk的fd字段，我就可以把fd指向我所希望的地址A，那么这个A就成功加入list。

#### 2.补充知识

##### （1）fastbins

Fast bins 可以看着是 **small bins 的一小部分 cache**，默认情况下， fast bins **只 cache 了 small bins 的前 7 个大小的空闲 chunk**，也就是说，对于 SIZE_SZ 为 4B 的平台【32bits的平台】， fast bins 有 7 个 chunk 空闲链表（ bin），每个 bin 的 chunk 大小依次为 16B， 24B， 32B， 40B， 48B， 56B， 64B；<u>对</u>
<u>于 SIZE_SZ 为 8B 的平台【64bits的平台】， fast bins 有 7 个 chunk 空闲链表（ bin），每个 bin 的 chunk 大小依次为 32B， 48B， 64B， 80B， 96B， 112B， 128B。</u>【每个bin中的chunk的size都一致】

另外，fastbins中每个bin是LIFO的栈，后进先出

##### （2）根据size确定bin

glibc 在执行分配操作时，若块的大小符合 fast bin【64位系统是32-128B】，则会在对应的 bin中寻找合适的块。

此时 glibc 将根据候选块的 size 字段计算出 fastbin 索引【即找到fastbins中的满足size的那个bin】，然后与对应 bin 在 fastbin 中的索引进行比较，如果二者不匹配，则说明块的 size 字段遭到破坏。<u>所以如果在fast bins中进行伪造，那么需要 fake chunk 的 size 字段被设置为正确的值。</u>

glibc 检查代码:

```c++
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \  
	((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)  
	if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))    
	{      idx = fastbin_index (nb);//根据用户malloc的大小确定在fastbins中的第idx个bin进行分配      
			[...]      
			
			if (victim != 0) //找到一个可分配的空闲chunk       
			{          
				if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0)) 
                    //获取这个chunk的size字段，计算对应的fastbins的索引，看看是否和idx相同     
				{		errstr = "malloc(): memory corruption (fast)";
                		[...]            
                }            
                [...]        
            }    
    }
```

#### 3.回到正题——利用double free伪造一个栈上的chunk

和上一题类似，进行double free，此时fastbins中的0x20 bin为`[0x603000,0x603020,0x603000]`

![stack1](/img/how2heap/fastbin_dup_stack1.png)

注意：free的chunk没有标志位M，也就是保持0了。

接下来我们再来看看stack_var的情况：

![stack1](/img/how2heap/fastbin_dup_stack2.png)

根据code中的提示`"The address we want malloc() to return is 8+(char *)&stack_var`，也就是说我们希望malloc一个chunk的用户地址【malloc的返回值】为0x7fffffffddf8。

接下来malloc了一个**size同样为8**的chunk，此时fastbins中的0x20 bin由`[0x603000,0x603020,0x603000]`变为`[0x603020,0x603000]`【注意fastbins中的地址连接是对应chunk的最低地址（即指向prev_size的指针）而不是返回给用户地址的地址（即指向fd的指针），**下文中用chunk头地址和chunk mem地址来区别**】

![stack1](/img/how2heap/fastbin_dup_stack3.png)

通过打印d变量，我们可以确定，malloc返回的`0x603010`【是malloc的，因而为mem地址】对应的chunk头地址为`0x603000`.【print d，打印d指针指向的地址；print &d，打印d指针存储的地址，此时d是局部变量，故是栈上地址；print *d，答应d指针指向地址下的内容】

![stack1](/img/how2heap/fastbin_dup_stack4.png)

再次malloc以后，fastbins中的0x20 bin由`[0x603020,0x603000]`变为`[0x603000]`【但是由于0x603000的chunk的fd指针指向0x603020，而0x603020的chunk的fd指针又指向0x603000，因此这个bin对应size的malloc会依次不断分配这两个地址】=》也就是说，bin是通过fd/bk进行指示连接的。

![stack1](/img/how2heap/fastbin_dup_stack5.png)

既然通过修改fd和bk可以将伪造的chunk纳入bin中，那么现在我们要在栈上伪造一个chunk，就需要把一个可控的free chunk的fd写成栈上伪造chunk的chunk头地址就行！

目前我们通过double free，得到了一个即在fastbin中，又在malloc的chunk，即d【对应chunk为0x603000】，也就是说可以对chunkd的fd字段进行操作。如果把d的fd字段设置为一个在栈上伪造好的**chunk头地址**，那么就可以把栈上伪造的chunk，纳入0x20 bin了。

但是前面在glibc 检查代码中提到了，伪造chunk还需要把size字段设置好，否则无法绕过检查。

既然现在只能控制0x20 bin的chunk，那么伪造chunk的size字段必须是0x20，或者0x21。

故`stack_var = 0x20;`，则chunk头地址为`&stack_var-8`【和伪造在哪里无关，prev_size的位置就是比size的位置低8B】

![stack1](/img/how2heap/fastbin_dup_stack6.png)

![stack1](/img/how2heap/fastbin_dup_stack11.png)

接下来将chunkd的fd字段修改为`&stack_var-8=0x7fffffffdde8`，这时候查看fastbins就可以看到由`[0x603000]`变为`[0x603000,0x7fffffffdde8]`

![stack1](/img/how2heap/fastbin_dup_stack7.png)

但是fastbin中为什么有0x603010呢？记住bin是由fd和bk进行链接控制的。

我们查看0x7fffffffdde8所在chunk，可以发现，对应的fd字段确实是0x603010。所以0x20 bin中0x7fffffffdde8 free chunk指向的下一个free chunk就是0x603010。

哎这地址有点巧啊，而且多次运行，fd字段依旧是0x603010，why?

看看局部变量的定义顺序把，先定义stack_var，然后定义了int \*a,int \*b,int \*c。所以地址依次是0x7fffffffddf0，0x7fffffffddf8，0x7fffffffde00。所以fd字段的位置恰好是int *a所在的位置，而int *a在malloc的时候得到`0x603010`此后也没有置为NULL，因此fd字段就是0x603010。

![stack1](/img/how2heap/fastbin_dup_stack8.png)

最后malloc(8)，注意这个size一定要保持和前面的统一，使得其会在0x20 bin进行分配，从而得到了返回的chunk地址为`0x7fffffffdde8 +16 =0x7fffffffddf8`，**这样的话，之后你就可以操作栈上的数据，进行栈溢出等攻击了。**

![stack1](/img/how2heap/fastbin_dup_stack9.png)

![stack1](/img/how2heap/fastbin_dup_stack10.png)

#### 4.总结

这个double free 造成任意修改栈地址的攻击流程： 这是基于上面的fastbin_dup，是可以<u>将栈上的地址通过malloc返回回来。但是可利用的不仅仅是stack，而是我们可设置的任意值【可能是bss段等】。</u>

利用条件：double free+栈上任意可写变量。

##### fastbin_dup_into_stack实现流程

<u>第一步：初始化，把上一个fastbin_dup都做一遍</u>

```
     malloc=>a
     malloc=>b
     free a
     free b
     free a
```

这样fastbins中有了三个fastbin：a=>b=>a。 

<u>第二步：伪造一个假的fastbins链表(通过写堆头)</u>

```
    malloc=>c(a)
    malloc=>b(b)
    rewrite c->fd=fake_value
    rewrite fake chunk size by stack var
```

在这里通过伪造fd，可以导致fastbin中出现了第四个free chunk：a=>fake_value 

<u>第三步：成功分配到栈上的地址，造成可任意修改</u>

```
    malloc=>d(a)
    malloc=>fake_value
```

返回的fake_value，我们就能对对应地址的值进行任意的修改了。

## fastbin_dup_consolidate

> 不知道为什么，网上的很多how2heap解析都跳过了这个

前面`fastbin_dup`介绍了一个 fast double free 的绕过机制，通过在free 同一个 chunk中的中间插入对另外一个chunk 的free，即free(a)->free(b)->free(a)，从而实现double free。

**而这里的思路是**：通过分配large bin来触发malloc_consolidate()【此时p1已经不在fastbin中】，而此时p1被放到unsorted bin，那么既然p1不在fast bin top自然就可以再次free，即绕过了double free。

#### 1.malloc的分配过程

推荐曾经写的[「堆漏洞」堆结构复习之malloc和free的过程]([https://spidermana.github.io/2019/04/19/%E5%A0%86%E7%AC%94%E8%AE%B0/](https://spidermana.github.io/2019/04/19/堆笔记/))

以下简述一下：

- H = （user malloc size + SIZE_SZ）align 2*SIZE_SZ
- **fast bins中尝试分配【精确匹配】：**H<= max_fast (max_fast 默认为 64B)，则在fastbin中分配。fast bin中没有则下一步，到small bin中找
- **small bins中尝试分配：【精确匹配】**H大小是否处在 small bins 中【即判断H < 512B是否成立】
  - 找到则从该 bin 的尾部摘取一个**恰好满足大小**的 chunk。
- **整合fast bins到unsorted bin：**遍历 fast bins 中的 chunk，将相邻的 chunk 进行合并， 并链接到 unsorted bin【malloc_consolidate】。
- **unsorted bin中尝试分配：**如果 unsorted bin 只有一个 chunk，并且这个 chunk 在上次分配时被使用过。且H大小属于 small bins，并且 chunk 的大小>=H，这种情况下就直接将该 chunk 进行切割，分配结束。
  - 否则整合unsorted bin中的chunk依据大小分别放到small bins或large bins中。
  - 到了这一步，说明需要分配的是一块大的内存，或者 small bins 和 unsorted bin 中都找不到合适的 chunk，并且 <u>fast bins 和 unsorted bin 中所有的 chunk 都清除干净了</u>。
- **在large bins中尝试分配：**按照最佳匹配算法分配，找一个合适的 chunk，切出H大小，并将剩下的部分链接回到 bins【根据大小放入small，large或是fast】
  - 不需要精确匹配
- **在top chunk中尝试分配：**判断 top chunk 大小是否满足所需 chunk 的大小，如果是，则从 top chunk 中分出H，完成，剩下的部分继续作为top chunk。
  - 否则，如果是主分配区，调用 sbrk()，增加 top chunk 大小；如果是非主分配区，调用 mmap 来分配一个新的 sub-heap，增加 top chunk 大小；或者使用 mmap()来直接分配。
- **H>mmap 分配阈值[128KB]：**直接用mmap分配，成为mmaped chunk【使用 mmap 系统调用为程序的内存空间映射一块H align 4kB 大小的空间】，完成。

#### 2.large bin

在 SIZE_SZ 为 4B 的平台上，大于等于 512B 的空闲 chunk，或者，**在 SIZE_SZ 为 8B 的平台上，大小大于等于 1024B =0x400的空闲 chunk**，由 sorted bins 管理。 

Large bins 一共包括 63 个 bin，每个 bin 中的 chunk 大小不是一个固定公差的等差数列， 而是分成 6 组 bin，每组 bin 是一个固定公差的等差数列，每组的 bin 数量依次为 32、 16、 8、 4、 2、 1，公差依次为 64B、 512B、
4096B、 32768B、 262144B 等。

#### 3.small bin

在 SIZE_SZ 为 4B 的平台上， small bins 中的 chunk 大小是以 8B 为公差的等差数列，最大
的 chunk 大小为 504B，最小的 chunk 大小为 16B，所以实际共 62 个 bin。分别为 16B、 24B、32B，……， 504B。**在 SIZE_SZ 为 8B 的平台上**， small bins 中的 chunk 大小是以 16B 为公差的等差数列，最大的 chunk 大小为 1008B，最小的 chunk 大小为 32B，所以实际共 62 个 bin，分别为 **32B**、 48B、 64B，……， **1008B**。

#### 4.解析源码+debug

```c++
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400); //因此满足64位os下的large bin要求
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

首先看代码，先申请了两个fastbin分别为p1和p2，此时bins均为空。

```shell
pwndbg> heap
0x602000 FASTBIN {
  prev_size = 0x0, 
  size = 0x51, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 FASTBIN {
  prev_size = 0x0, 
  size = 0x51, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020a0 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x20f61, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

然后释放了一个p1，将其加入fastbins中【64bits平台下，fastbin最大的chunk为128B，所以0x50属于fastbin】。

![con1](/img/how2heap/fastbin_dup_con1.png)

再申请了一个0x400的largebin去触发漏洞【64bits的平台大于1024B=0x400B的chunk都属于largebin】，这是由于在申请largebin的时候会首先根据 chunk 的大小获得对应的 large bin 的 index。

接着判断当前分配区的 fast bins 中是否包含 chunk，如果有，调用 malloc_consolidate() 函数，合并 fast bins 中的 chunk，并将这些空闲 chunk 加入 unsorted bin 中。因为这里分配的是一个 large chunk，所以 unsorted bin 中的 chunk 按照大小被放回 small bins 或 large bins 中。【对于p1来说经历了：fast bin->unsorted bin->small bin】

看看 large bin的分配

```c++
/*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av)) //如果由fastchunk就触发malloc_consolidate
        malloc_consolidate (av);
    }
```

malloc_consolidate() 函数的处理：

- 这时候有fast bin 0x50：0x602000【p1】加入unsorted bin，加入的时候如果有相邻就会合并，否则只是简单插入unsorted bin。
- 显然现在unsorted bin中唯一的chunk的大小还是不够0x400，因而触发整合unsorted bin中的chunk依据大小分别放到small bins或large bins中。
- 这时会把0x602000【p1】整合到small bins。

```c
   10   free(p1);
   11 
   12   void* p3 = malloc(0x400);
 ► 13   fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
   14   fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
   15   free(p1);
──────────────────────────────────────────────────────────────
pwndbg> heap
0x602000 FASTBIN {
  prev_size = 0x0, 
  size = 0x51, 
  fd = 0x7ffff7dd1bb8 <main_arena+152>, 
  bk = 0x7ffff7dd1bb8 <main_arena+152>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602050 {
  prev_size = 0x50,  //此时物理相邻的chunk=0x602000已经free，因此P标志位为0【size字段改变】，由prev_size指示物理相邻的前一个chunk的size。【prev_size字段改变】
  size = 0x50, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020a0 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x411, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6024b0 PREV_INUSE {
  prev_size = 0x0, 
  size = 0x20b51, 
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
unsortedbin
all: 0x0
smallbins
0x50: 0x7ffff7dd1bb8 (main_arena+152) —▸ 0x602000 ◂— 0x7ffff7dd1bb8  //可以看到p1=0x602000被整合到了small bins
largebins
empty
pwndbg> 
```

这个时候我们就可以再次释放 p1，实现double free。（这是由于p1不是fast top，所以p1可以被释放）。

```assembly
   15   free(p1);
 ► 16   fprintf(stderr, "Trigger the double free vulnerability!\n");
   17   fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
   18   fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
   19 }
──────────────────────────────────────────────────────────────
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x602000 ◂— 0x0
0x60: 0x0
#但是我不知道为什么在terminal的时候可以正常运行，而pwndbg的时候不行【并且看不到两个bins都有0x602000】，可能会由一些pwndbg提供的内存检测机制
#pwndbg输出
pwndbg> n
Trigger the double free vulnerability!
#terminal输出
$ ./fastbin_dup_consolidate 
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x17ee010 0x17ee010
```

这个时候，我们既有fastbins中的 chunk p1 也有small bins 的chunk p1。

我们可以malloc两次，第一次从fastbins取出，第二次从small bins中取出【从前面malloc的过程可知，先尝试在fast bin中分配，再尝试从small bin中分配，因此依次取出"两个"p1】，且这两块新 chunk 处于同一个位置。

## unsafe_unlink

> 重头戏！来了！准备绕晕！