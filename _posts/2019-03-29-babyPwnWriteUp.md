![Linux环境中堆栈和堆相关内存损坏的基本原理和调试方法介绍](https://www.4hou.com/uploads/20170720/1500541301124000.png)



在没有开PIE的情况下，IDA和gdb vmmap中给出的地址都是真实地址。

如果开了PIE【pie的机制就是在某个及地址的基础上偏移】，那么给出的地址是偏移。

- 后三位是偏移
- 要找基地直来算真实地址

```c++
//使用pwntools中的shellcode生成方法，这里要区分32和64位
32位:
context(os='linux',arch='i386',log_level='debug')
asm(shellcraft.i386.linux.sh())
 
64位:
context(os='linux',arch='amd64',log_level='debug')
asm(shellcraft.amd64.linux.sh())
```

 atol()会扫描参数nptr[字符](https://baike.baidu.com/item/%E5%AD%97%E7%AC%A6)串，跳过前面的空格字符(就是忽略掉字符串左空格的意思)，直到遇上数字或正负符号才开始做转换，而再遇到非数字或字符串结束时('\0')才结束转换，并将结果返回。

返回值：返回转换后的[长整型](https://baike.baidu.com/item/%E9%95%BF%E6%95%B4%E5%9E%8B)数。如果传入的字符串为空，或者字符串包含的内容非阿拉伯数字序列，则函数返回默认值0。