

## 专有名词

NDSS 会议（全称The Network and Distributed System Security Symposium）是和CCS，USENIX SECURITY及IEEE S&P并称的计算机系统安全领域的四大顶级会议之一。

TEE:可信执行环境。TEE是与设备上的**Rich OS（通常是Android等**）并存的运行环境，并且给Rich OS提供安全服务。它<u>具有其自身的执行空间，比Rich OS的安全级别更高</u>，但是比起安全元素（**SE，通常是智能卡**）的安全性要低一些。但是TEE能够满足大多数应用的安全需求。从成本上看，TEE提供了安全和成本的平衡。

- TEE概念基于ARM的TrustZone技术

Soc： SoC称为系统级芯片，也有称片上系统，意指它是一个产品，是一个有专用目标的集成电路，其中包含完整系统并有嵌入软件的全部内容。

- SoC=System On Chip=System On a Chip=系统级芯片=片上系统

- - 典型组成包括：CPU、一些存储器（RAM，ROM）、外设peripheral【LCD显示屏、音视频DSP、图像处理器GPU】
  - 集成的东西足够，甚至可以组成一个小的系统了
  - 所以才叫做 ：（都把一整个系统）System （都集成在）On（了一个芯片）Chip（上）

REE: Rich Execution Environment：由Rich OS提供的环境，处于TEE之外, 在此环境中的东西被认为是untrusted.

ROS: Rich OS：通常是指比TEE里面的OS要来得具有更多功能的OS, 以功能、效能为主要考量, 而不是安全.因为很肥, 所以跑在TEE外, 也就是REE.

DRM：英文全称Digital Rights Management, 可以翻译为：数字版权管理。 由于数字化信息的特点决定了必须有另一种独特的技术，来加强保护这些数字化的音视频节目内容，文档、电子书籍的版权

TA：可信应用

CA：客户端应用，CA(clientapplicationrunninginREE)

GP：GlobalPlatformis a nonprofit organization that creates and publishes specifications【 technical standard、说明书、要求标准、规范】 for secure chip technology

SE：Secure Element【安全元素】，常常指的是智能卡

TUI：可信UI是指在关键信息的显示和用户关键数据（如口令）输入时，屏幕显示和键盘等硬件资源完全由TEE控制和访问，而Rich OS中的软件不能访问

OMTP：开放移动终端平台组织、OMTP工作组致力于为移动设备制造商、相关的软件与硬件供应商建立开放性架构，以帮助他们开发出开放性的移动终端平台。The Open Mobile Terminal Platform (OMTP) was a forum created by mobile network operators to discuss standards with manufacturers of mobile phones and other mobile devices. During its lifetime, the OMTP included manufacturers such as Huawei, LG Electronics, Motorola, Nokia, Samsung and Sony Ericsson

TCB是Trusted Computing Base的简称，指的是**计算机内保护装置的总体**，包括硬件、固件、软件和负责执行安全策略的组合体。它建立了一个基本的保护环境并提供一个可信计算机系统所要求的附加用户服务。

相关名词整理：http://webcache.googleusercontent.com/search?q=cache:KJghfH_2KKsJ:wp.mlab.tw/%3Fp%3D1999+&cd=2&hl=zh-CN&ct=clnk



## TEE入门

TEE介绍：https://blog.csdn.net/braveheart95/article/details/8882322

TEE白皮书：https://wenku.baidu.com/view/ad503b975ef7ba0d4b733b39.html