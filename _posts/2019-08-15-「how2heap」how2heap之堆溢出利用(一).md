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

##### (1)inuse chunk的格式

一个使用中的 chunk（使用中，就是指还没有被 free 掉）在内存中的样子【不同bins大同小异】如图所示： 

![firstfit1](/img/how2heap/fastbin_dup1.png)

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

##### （1）debug

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



## unsafe_unlink