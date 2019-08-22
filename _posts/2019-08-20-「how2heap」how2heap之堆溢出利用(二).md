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

## House of Spirit

在2009年，Phrack 66期上也刊登了一篇名为"Malloc Des-Maleficarum"的文章，对前面提到的这几种技术进行了进一步的分析，在这其中，House of Spirit是与fastbin相关。

#### 攻击思路

House of spirit 的主要利用fastbin，其基本思路如下:

1. 用户能够通过这个漏洞控制一个free的指针*P*
2. 在可控位置(.bss,stack,heap)上构造一个fake fastbin chunk
3. 将*P*修改为fake fastbin chunk 的chunk address，并且将其free到*Fastbins[i]*中去
4. 下次malloc一个相应大小的fastbin时就能够返回fake fastbin chunk的位置，实现write anything anywhere

简单来说就是，通过在任意可控内存区构造一个fake chunk，free这个伪造chunk，使得内存allocator错误分配到我们可控的内存区域，进而达到write anything anywhere的效果。

#### 攻击原理



#### 攻击效果



#### 参考链接

- [浅析Linux堆溢出之fastbin](https://www.freebuf.com/news/88660.html)
- [Horse of spirit from ret2forever](https://tac1t0rnx.space/2018/02/14/horse-of-spirit/)

[https://qrzbing.cn/2019/07/08/how2heap-2/#%E8%A7%A3%E9%87%8A](https://qrzbing.cn/2019/07/08/how2heap-2/#解释)

https://blog.csdn.net/qq_29343201/article/details/59477082

https://www.anquanke.com/post/id/86809

https://xz.aliyun.com/t/2582#toc-6