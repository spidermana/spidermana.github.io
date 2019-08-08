---
title:内存分析工具volatility+内存dump工具LiME
date: 2019-01-16 9:40:00
tags: descrete
---



# 内存工具使用

使用LiME + volatility2.4进行内存读取

LiME下载地址：https://github.com/504ensicsLabs/LiME

volatility2.4下载地址：https://github.com/volatilityfoundation/volatility

lmg-master下载地址:https://github.com/halpomeranz/lmg/

- 官网：https://www.volatilityfoundation.org/
- **git提交时报错 错误信息是 RPC failed;** 
  - 网络问题
  - 或是一次clone/push太多，超过git提交的范围【远程HTTP传输请求数据时最大的缓存字节数，默认时1M字节，默认能满足大多数请求】，就提交失败
  - 解决：配置git缓存值，`sudo git config --global http.postBuffer 524288000`

*注意工具的内核版本要求*

**查看系统及内核版本命令**

- 查看发布版本号
  - cat /etc/issue
  - lsb_release -a

-  查看内核版本号
  - uname -sr
  - uname -a

## 环境安装

##### 1.LIME在github上clone到本地就行。

##### 2.volatility在github上clone到本地

- 以后安装volatility源码【若需要在其他的Python脚本中import volatility，则需要进行安装】：在命令行下切换到Volatility源码包的主目录,然后执行安装命令:

  ```
  python setup.py install
  ```

- 如果不想安装源码包,也可以直接执行如下命令:

  ```
  python vol.py -h
  ```

- ![vol1](C:\Users\asus\spidermana.github.io\assets\img\vol1.jpg)

- 在https://pypi.org/中搜索pycrypto[2.6.1]和distorm3模块，Download file，解压后切换到模块目录，,执行安装命令:

  ```
  sudo python setup.py install
  ```

  - 安装pycrpto的时候可能会出现错误

    ![vol2](C:\Users\asus\spidermana.github.io\assets\img\vol2.jpg)

  - 缺少python的dev，执行`sudo yum  install python-devel`之后，再重新安装pycrpto

- 此时再进入volatility目录，执行`python vol.py -h`发现没有报错了，安装完成，列出了可用的一些命令

  ![vol3](C:\Users\asus\spidermana.github.io\assets\img\vol3.jpg)



## Dump Linux memory

1.编译安装需要内核头文件，安装的结果在/usr/src/kernels目录里。

```
sudo yum install kernel-devel
```

- **如果某个程序需要内核提供的一些功能，它就需要内核的C header来编译程序**，这个时候kernel-devel里面的东西就用上了。
- 比如 nvidia 和 ati 的官方显卡驱动，alsa-driver 声卡驱动，他们都需要<u>编译一个放在内核里面运行的模块，</u><u>编译这个模块就需要内核的header文件才能顺利编译</u>。
- 当然，**kernel-devel 不光是 C Header 文件，它还有内核的配置文件，以及其他的开发用的资料。**
- 如果安装的目录名（显示为kernel版本）与 **uname -r** 不一样，说明系统需要升级了，需要sudo yum upgrade一下。
  - ![lime1](C:\Users\asus\spidermana.github.io\assets\img\lime1.jpg)

2.进入LiME目录下的src，进行make，生成新文件lime.ko，并重新命名为lime-3.10.0-862.el7.x86_64.ko

- ![lime2](C:\Users\asus\spidermana.github.io\assets\img\lime2.jpg)

- <u>mv命令</u>是move的缩写，可以<u>用来移动文件或者将文件改名</u>（move (rename) files），是Linux系统下常用的命令，经常用来备份文件或者目录。

  1．命令格式：
      mv [选项] 源文件或目录 目标文件或目录

  2．命令功能：

  - 视mv命令中第二个参数类型的不同（是目标文件还是目标目录），mv命令将文件重命名或将其移至一个新的目录中。
  - 当第二个参数类型是文件时，mv命令完成文件重命名，第二个参数为新名称。
  - 当第二个参数是已存在的目录名称时，源文件或目录参数可以有多个，mv命令将各参数指定的源文件均移至目标目录中。

3.简述LiME的使用：

```
Detailed documentation on LiME’s usage and internals can be found in the “doc” directory of the project. LiME utilizes the insmod command to load the module, passing required arguments for its execution.
```

4.在生成.ko文件的目录下，执行`insmod ./lime-xxxx.ko "path=fullmem.lime format=lime"`，dump整个内存

- ![lime3](C:\Users\asus\spidermana.github.io\assets\img\lime3.jpg)

- ```
  insmod ./lime.ko "path=<outfile | tcp:<port>> format=<raw|padded|lime> [dio=<0|1>]"
   
  path (required):   outfile ~ name of file to write to on local system (SD Card)
          tcp:port ~ network port to communicate over
   
  format (required): raw ~ concatenates all System RAM ranges
          padded ~ pads all non-System RAM ranges with 0s
          lime ~ each range prepended with fixed-size header containing address space info
   
  dio (optional):    1 ~ attempt to enable Direct IO
          0 ~ default, do not attempt Direct IO
   
  localhostonly (optional):  1 restricts the tcp to only listen on localhost, 0 binds on all interfaces (default)
  ```

- 在目录下生成一个与内存大小一样的fullmem.lime文件

参考视频：https://www.youtube.com/watch?v=_7Tq8dcmP0k

## 分析linux memory

1. 要分析内存内容，需要指定内存所在系统的格式，需要生成配置文件。在volatility有一些配置文件，但是不一定好用，需要准备生成profile文件的工具。
2. 进入volatility/tools/linux下执行make，可能会缺少dwarfdump，而安装dwarfdump需要安装libelf
   - ![vol4](C:\Users\asus\spidermana.github.io\assets\img\vol4.jpg)

   - dwarfdump：https://github.com/tomhughes/libdwarf

     - ```
       Download the tar file.
       tar xzf libdwarf-<version date extension>.tar.gz
       cd dwarf-<version date extension>
       ./configure
       make
       cd ../dwarfdump
       ./configure
       make
       ```

   - zlib is available in source from http://zlib.net

   - libelf is available in source from http://www.mr511.de/software/
3. 继续make

   - 编译安装完成后，有可能会报libelf.so.0找不到，但是在/usr/lib/local/目录下这个文件是有的。只要做一个软链，链到/usr/lib64/libelf.so.0就可以了。
4. 

参考视频：https://www.youtube.com/watch?v=1PAGcPJFwbE



### volatility安装与使用

- 安装官方链接：https://www.volatilityfoundation.org/

- 参考说明：https://github.com/volatilityfoundation/volatility

- 使用教程：https://github.com/volatilityfoundation/volatility/wiki

- 安装教程：https://github.com/volatilityfoundation/volatility/wiki/Installation

  - 建议安装：[Volatility 2.6 Linux Standalone Executables (x64)](http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip)

  - 根据官网说明：If you're **using the standalone** Windows, Linux, or Mac executable, no installation is necessary - just run it from a command prompt. **No dependencies are required, because they're already packaged inside the exe.**

  - linux系统要求:

    ```
    Linux: 
    * 32-bit Linux kernels 2.6.11 to 4.2.3
    * 64-bit Linux kernels 2.6.11 to 4.2.3
    * OpenSuSE, Ubuntu, Debian, CentOS, Fedora, Mandriva, etc
    
    ```

  - 支持的内存类型:

    ```
    Volatility supports a variety of sample file formats and the
    ability to convert between these formats:
    
      - Raw linear sample (dd)
      - Hibernation file (from Windows 7 and earlier)
      - Crash dump file
      - VirtualBox ELF64 core dump
      - VMware saved state and snapshot files
      - EWF format (E01) 
      - LiME format
      - Mach-O file format
      - QEMU virtual machine dumps
      - Firewire 
      - HPAK (FDPro)
    ```

  - python要求: Python 2.6 or later, but not 3.0

    





## 参考文章

- https://blog.csdn.net/Fly_hps/article/details/79961707
- https://blog.csdn.net/terminatorsong/article/details/76473546
- https://blog.csdn.net/soda_199/article/details/79644303
- https://blog.csdn.net/Fly_hps/article/details/79961707
- https://blog.csdn.net/qingchenldl/article/details/78447003

