### Howard: a Dynamic Excavator for Reverse Engineering Data Structures

#### 概述

Howard从C二进制文件中提取数据结构without symbol tables【无需符号表】。我们的结果比以前的方法更准确 - 足以<u>让我们生成自己的（部分）符号表</u>而无需访问源代码。

与大多数现有工具不同，我们的系统使用动态分析（在基于QEMU的仿真器上）并<u>通过跟踪程序如何使用内存来检测数据结构</u>。

Howard的**主要目标是为现有的反汇编程序和调试程序提供有关数据结构和类型的信息，以简化逆向工程。**为此，它会**自动生成可供所有常用工具使用的调试符号。**

同时获得的数据结构，可以增强现有的二进制文件的安全性。具体来说，我们表明我们可以保护遗留二进制文件免受缓冲区溢出。

#### 前言

因为真正的程序往往围绕着他们的数据结构，对这些数据结构的忽视/无知，使得逆向已经很复杂工程、项目更慢而且更痛苦。

最常见的方法是基于静态分析技术，如价值集分析[8]，聚合结构识别[38]及其组合[39]。

The most common approaches are based on static analysis techniques like value set analysis [8], aggregate structure identification [38] and combinations thereof [39]. 

静态分析太有限，太低效了，因而提出了动态分析数据结构。

较为著名的方法有：Laika [22]和Rewards [31]。

Laika的检测既不精确又限于聚合结构（即，它将结构中的所有字段混合在一起）。This is not a problem for Laika’s application domain – estimating the similarity of different samples of malware by looking at the approximate similarity of their data structures. 【通过查看其数据结构的近似相似性来估计不同恶意软件样本的相似性】

在（2010）NDSS中，提出了Rewards技术。其想法很简单：只要程序调用一个众所周知的函数（比如系统调用），我们就知道所有参数的类型 - 所以我们相应地标记这些内存位置。接下来，我们向后传播此类型信息并通过执行程序转发。
例如，whenever labeled data is copied, the label is also
assigned to the destination【标签会在执行中传递】。Rewards技术是动态分析技术。但是该技术仅恢复在系统调用（或众所周知的库函数）的参数中直接或间接出现的那些数据结构。这只是程序中所有数据结构的一小部分。所有内部【internal 】的变量和数据结构仍然是不可见的，隐形的。

故，在本文中，我们描述了一种称为的新技术Howard——改善了这些现有技术，它是Reward的补充，但功能更强大,因为它也找到了内部变量。

Howard builds on dynamic rather than static analysis,following the simple intuition that memory access patterns reveal much about the layout of the data structures【通过观察内存访问模式揭示数据结构的布局。】. Something is a structure, if it is accessed like a structure, and an array, if it is accessed like an array. And so on.

Howard’s results depend on the code that is covered at runtime – it will not find data structures in code that never executes【Howard的结果取决于运行时所涵盖的代码，因此不会执行的代码涉及数据结构是不会找得的】

![1562551388897](C:\Users\asus\spidermana.github.io\assets\img\howard1.png)

如图1所示，我们使用现有的代码覆盖工具（如KLEE）和测试套件来覆盖尽可能多的应用程序code，然后执行应用程序以提取数据结构。

Howard显着提升了现有技术水平，例如，我们是第一个可以提取：

- 堆和堆栈上的精确数据结构;
- 不仅是聚合结构，还包括单个领域;
- 嵌套数组等复杂结构。