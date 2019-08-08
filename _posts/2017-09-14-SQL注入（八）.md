---
layout: post
title: SQL注入（八）
desc: ""
keywords: ""
date: 2016-11-01
categories: []
tags: []
---

<blockquote>
  薯片果然还是要乐事原味
</blockquote>

<h2>Less-11</h2>

刷完了Get型注入，于是我们来到了Post型注入

Post型注入的一个特点就是不会再URL栏看到任何的参数，他的数据传递是包含在HTTP报文里的，于是我们能通过Burp抓包去获取这些数据，进行注入

这时候又能祭出神器Hackbar，勾上Enable Post data，我们就能继续注入了

<h3>特点</h3>

一上来就看到了一个登陆框，啊万恶的登陆框…

将Username和Password均填入123，抓包情况如下：

<img src="http://oc42vgpoj.bkt.clouddn.com/less11_burp.png" />

登陆失败时显示的是Login Attempt Failed

<img src="http://oc42vgpoj.bkt.clouddn.com/less11_error_%2527.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/less11_error_%2527.png" />

查看了一下后台的语句，发现是

<pre class="lang:tsql decode:true" title="SQL">SELECT username, password FROM users WHERE username='$uname' and password='$passwd'
LIMIT 0,1</pre>

<h3>注入检测</h3>

在用户名后面输入了一个单引号，发现报错

大概能猜出是以单引号闭合的

<h3>Payload</h3>

其实之前说的万能密码也是一个原理，都是通过合并构造恒为真的语句并且注释掉后面的语句，来实现无密码登陆

经过测试，发现了一些有趣的细节……

<pre class="lang:tsql decode:true" title="Test Payload">uname=123' or 1=1--&amp;passwd=123&amp;submit=Submit // 错误
uname=123' or 1=1 -- &amp;passwd=&amp;submit=Submit // 正确
uname=123' or 1=1 # &amp;passwd=123&amp;submit=Submit // 正确
uname=123' or 1=1 #&amp;passwd=123&amp;submit=Submit // 正确</pre>

哦？哦？看来注释和后面语句是要加个空格的对吧 = =

查询表名

<pre class="lang:tsql decode:true" title="Payload">uname=123%27 union select 1, table_name from information_schema.tables 
where table_schema=database() -- &amp;passwd=&amp;submit=Submit</pre>

<img src="http://oc42vgpoj.bkt.clouddn.com/less11_table_name.png" />

后面同理了，省略。

<h2>Less-12</h2>

道理和Less-11一样，不过这次是双引号和括号闭合的

<h3>语句猜测</h3>

这个就很明确了，直接在用户名输入123"，报错如下：

<img src="http://oc42vgpoj.bkt.clouddn.com/less12_error.png" />

很明显语句应该是类似

<pre class="lang:tsql decode:true  " title="SQL">SELECT username, password FROM users WHERE username=("$uname") and 
password=("$passwd") LIMIT 0,1</pre>

<h3>Payload</h3>

不用讲了吧，闭合好就行了