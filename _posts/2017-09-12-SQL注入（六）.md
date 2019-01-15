---
layout: post
title: SQL注入（六）
desc: ""
keywords: ""
date: 2016-09-27
categories: []
tags: []
---

[audio mp3="http://chiahao.top/wp-content/uploads/2016/09/Altan-Daily-Growing-Altan..mp3"][/audio]

<blockquote>Daily Growing</blockquote>

<h2>Less1</h2>

<h3>前言</h3>

每篇无聊的博文都应该有一个有趣的前言，比如这一篇。静下心来刷一遍SQLi-labs

关于这个环境的搭建，我在Kali 2.0上直接安装好了Xampp，一步到位搞定了。然后把Sqli-labs文件放到了 <code>/opt/lampp/htdocs</code>文件夹下面，并修改了里面sql-connections文件夹下db-creds.inc文件的用户名和密码

使用命令 /opt/lampp/./lampp start 运行即可

在浏览器中输入地址<code>http://loaclhost/sqli-labs</code>即可开始

<h3>SQL报错</h3>

Less1为Get类型单引号字符型，因此构造<code>http://192.168.15.130/sqli/Less-1/?id=1'</code>，由于单引号没有闭合，会报错。

<h3>猜测语句</h3>

只能判断前面是有引号的，如果多加了一个引号就会出现错误。
<img src="http://oc42vgpoj.bkt.clouddn.com/quote_error.png" alt="quote_error" />
实际的语句如下

<pre class="lang:tsql decode:true">$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";</pre>

<h3>偏移</h3>

在语句中的LIMIT 0,1这一句是对查询结果的一个偏移，因为上面的语句会显示这个列中所有的行，我们需要对结果进行筛选显示在网页上。LIMIT语句第一个表示起点，第二个表示步长。因此这个语句将会显示第一行

同理，如果要显示第6-15行，我们需要使用LIMIT 5,,10来进行限制

<h3>注释</h3>

使用的浏览器客户端是Firefox，在实际操作的时候发现了很多坑。按理说MySql的注释符号有"+--+, -- （后面有空格）, #"，但是实际在操作的时候%,#,-- 都不能达到效果，需要将其转化为URL编码才能被正确的传到后台。

"#"对应的URL编码为%23，在Hackbar中很方便的可以进行编码

<h3>爆字段数</h3>

使用order by函数加上多行来爆字段，当数字为3时没有报错
<img src="http://oc42vgpoj.bkt.clouddn.com/column_3.png" alt="column_3" />

可以看到当数字加到4的时候提示没有该列，因此字段数为3。
<img src="http://oc42vgpoj.bkt.clouddn.com/column_4.png" alt="column_4" />
order by 1,2,3,4 表示按照1,2,3,4,列去排列查找到的数据，由于只有3列，当我们试图用第4列去排序的时候自然会报错。

<h3>查询数据库，版本，数据库用户</h3>

查找应使用union select函数，union select和前面的查找是并集的关系，由于显示的位置只有两个，我们必须让前面查找不出结果，这样就会显示我们需要查找的内容。比如把id设置为-1，注意在查找时仍然要闭合好前面的单引号。

<img src="http://oc42vgpoj.bkt.clouddn.com/database_version.png" alt="database_version" />

我们可以先使用union select 1,2,3来判断下网页上会显示哪一列，然后再把相应的位置来替换成需要的信息。

<img src="http://oc42vgpoj.bkt.clouddn.com/confirm.png" alt="confirm" />

查找以下项目来收集所需信息：
* 版本信息：version()
* 数据库信息：database()
* 用户信息：user()
* 当前用户：current_user()
* 数据库路径：@@datadir
* MySQL安装路径：@@basedir
* 操作系统：version_compile_os

在系统中真实的数据库具有以下结构：

<img src="http://oc42vgpoj.bkt.clouddn.com/database_real.png" alt="database_real" />

<h3>查询表</h3>

使用

<pre class="lang:tsql decode:true">union select 1,2,table_name from information_schema.tables where table_schema='数据库名' +--+</pre>

来查找表名

<img src="http://oc42vgpoj.bkt.clouddn.com/table_information.png" alt="table_information" />

由于只会显示一列，我们就可以通过LIMIT这个函数来确定要显示哪一个。比如"LIMIT 0,1","LIMIT 1,1"等，直到获取所有表名

<img src="http://oc42vgpoj.bkt.clouddn.com/table_information_4.png" alt="table_information_4" />

information_schema这个表储存了所有的信息，嗯之前提到过。

<h3>查询列</h3>

使用

<pre class="expand:true lang:tsql decode:true">union select 1,2,column_name from information_schema.columns where table_schema='数据库名' 
and table_name='表名' limit 0,1 +--+</pre>

来获取列的信息

<img src="http://oc42vgpoj.bkt.clouddn.com/get_column_name.png" alt="get_column_name" />

<h3>查询数据</h3>

使用

<pre class="lang:tsql decode:true">union select 1,2,username users limit 0,1 +--+</pre>

来获取具体的数据信息。
使用concat_ws函数可以获取多条数据并用符号分割开，例如

<pre class="lang:tsql decode:true ">concat_ws(char(32,58,32),username,password)</pre>

就可以同时显示出用户名和密码，用"空格、冒号、空格"来分割

<img src="http://oc42vgpoj.bkt.clouddn.com/get_information.png" alt="get_information" />

<h2>Less2</h2>

Less2后面的注入应该大致同理，预计只是语句拼接的方式不同或者会有一些更为复杂的情况，因此在这里写写这与Less1的区别。

<h3>判断</h3>

语句<code>?id=1'</code>报错，而<code>?id=1' and 1=1</code>依然无法正常显示，说明这一题不是字符型，而是整数型。因此猜测语句在拼接时<code>id=1</code>没有引号。

此处不需要闭合引号，可以直接去插入语句注入，方法与前一题同理。

<h2>Less3</h2>

<h3>判断</h3>

题目本身的Single Quote with Twist已经够迷茫了好么= =
使用最基本的语句<code>?id=1'</code>发现报错

<blockquote>
  You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''1'') LIMIT 0,1' at line 1
</blockquote>

注意，在观察这些报错的时候要去掉最外面一层单引号，因此它的提示信息实际上是<code>'1'') LIMIT 0,1</code>
发现多了一个括号没有闭合，因此需要补全那个括号，并把后面的内容注释掉来完成注入。
其他内容与前面同理

<h2>Less4</h2>

<h3>判断</h3>

依旧从单引号开始判断，发现单引号并没有任何反应。
换一下双引号，发现报错了

<blockquote>
  You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '"1"") LIMIT 0,1' at line 1
</blockquote>

原来这个是双引号加括号闭合的。

<pre class="lang:tsql decode:true  ">?id=1") and 1=1 +--+</pre>

其他同理

<h3>后记</h3>

真没想写到这么晚啊，但是还是很开心的真正走了一次流程，学到了很多东西。

不做咸鱼 : )