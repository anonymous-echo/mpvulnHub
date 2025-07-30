#  漏洞挖掘 | 记一次Spring横向渗透   
原创 zkaq-Tobisec  掌控安全EDU   2024-08-25 12:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  Tobisec 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 0x1 前言  
  
这篇文章给师傅们分享下，前段时间的一个渗透测试的一个项目，开始也是先通过各种的手段和手法利用一些工具啊包括空间引擎等站点对该目标公司进行一个渗透测试。前面找的突破口很少，不太好搞，但是后面找到了spring全家桶的相关漏洞，然后打了spring的很多漏洞，然后也是交了蛮多的漏洞报告的。  
## 0x2 信息收集+资产收集  
  
首先对这个公司进行信息收集，公司比较小然后利用爱企查也没有信息可以提供查询的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWQZEc2goibEZSw1Uy3L55vbwf4seZaLicUVnicEQMOu6wWRcqMFjSVs5HQ/640?wx_fmt=png&from=appmsg "")  
  
这里点击这个股份穿透图，这个是免费的不需要会员，然后如果你要对一个公司进行测试的话，可以利用这些拓扑图然后进行一个边缘资产的收集，进行外围打点之类的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW6ogIeGXiafeNULJSJPVNbgr4VWI8UoxWWg8ynj3UAANyLVNu8DeAYZQ/640?wx_fmt=png&from=appmsg "")  
  
下面就找到了改公司的股份公司，然后对改公司再进行一个信息收集和资产收集可以重点看下改公司的实缴资金以及相关知识产权，里面可以去测下这些web系统的相关漏洞，要是能打一般这样的系统都是一个通杀漏洞了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWYW9NkcZfcZjSxuKCLIHUAaFk7w8xg6FiaFrBSxcjl7Aicvia5V2Utjezw/640?wx_fmt=png&from=appmsg "")  
  
我这里使用onefor-all子域名扫描工具进行扫描  
```
python oneforall.py --target https://url/ run
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWe0gGrvgDct7BthaqjlEWzNkb7wjSdcb75FowoTklNqslbSgmUxNgjw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWCIQYhCeKcQic3MVviafibBQUxrGgDscEvohpM1DRMP0jcmpGGsyRUl9ng/640?wx_fmt=png&from=appmsg "")  
  
然后访问子域名，再利用一些插件进行信息收集，看看开放的端口什么的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWJeEna3LLaOQPwiaUhhB4VcX9Aibc1qdeDITS7WJzeZNnPrjQ3gHibGiajA/640?wx_fmt=png&from=appmsg "")  
  
然后找里面的子域名资产利用dirsearch进行目录扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWPEtkaiciao0TFCoL6njPxZCRpOV7Vv8eV4RI9KicEIG77z6YCuT2JOYyw/640?wx_fmt=png&from=appmsg "")  
  
后来通过FOFA资产检索，发现了下面这个网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWMRGqCqDWqj9AxwZ0lhl9F5miajdve1gMovHicpvtPFNIwqjz8oeIibQuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWHyEqiciaH14zUMia3Jl9Af6n2egrL5J4H0IbKO7uodGZRUOlwRbiagTN5Q/640?wx_fmt=png&from=appmsg "")  
## 0x3 漏洞猎杀  
### 漏洞一：druid漏洞  
  
这里通过检索druid关键字，发现子域名可能存在druid协议，那么就可以尝试打一波druid漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWFVzMShojYqO9icz1WYxCBux0ibsdiauLPVNVrSic9X54tV43RQ6Jc3Lgibg/640?wx_fmt=png&from=appmsg "")  
  
通过拼接druid的登录接口，发现确实存在druid登录后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWZndVTMnz6lM5VvcYCiaKz45XUmzCQjTv7WeU3Lp886tojiaEpA3CPcdg/640?wx_fmt=png&from=appmsg "")  
  
然后就可以使用druid的常见弱口令，发现成功可以登录druid后台，然后后面就可以使用druid工具打打nday啥的了  
```
常见用户:admin ruoyi druid
常见密码:123456 12345 ruoyi admin druid admin123 admin888
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWQChGNeFkbdKe8ffib9EAqycy293FINiafYXByzCwVhBB9RGNHrauibVkg/640?wx_fmt=png&from=appmsg "")  
### 漏洞二：spring-boot未授权漏洞  
  
上面既然发现了druid，那么我们就可以使用曾哥的spring-boot工具进行扫一波可以看到下面泄露了很多的未授权接口目录的信息，且泄露的页面长度很多  
```
python SpringBoot-Scan.py -u ip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWPmolpZwuAAfgNFOwxG0Sn7rianLG4D5hV9rNLqZQhYtzZrqz3RqPMmA/640?wx_fmt=png&from=appmsg "")  
  
下面泄露了很多的接口信息，下面可以进行挨个访问看看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWhdLQm3lSOlCN6YBjnUEtGMRpElbDicgCPabbqPAY3dURmT5zotKjh1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWmREpdFzIN2kvwlibHWyuyXXVq5PoGdmukJQJftLadRiaYV4ibq1ec7GPA/640?wx_fmt=png&from=appmsg "")  
  
下面是常见的spring-boot接口泄露的相关信息，都可以去尝试访问下  
```
/actuator
查看有哪些 Actuator端点是开放的。

/actuator/auditevent
auditevents端点提供有关应用程序审计事件的信息。

/actuator/beans
beans端点提供有关应用程序 bean 的信息。

/actuator/conditions
conditions端点提供有关配置和自动配置类条件评估的信息。

/actuator/configprops
configprops端点提供有关应用程序@ConfigurationPropertiesbean的信息。

/actuator/env 
查看全部环境属性，可以看到 SpringBoot 载入哪些 properties，以及 properties 的值（会自动用*替换 key、password、secret 等关键字的 properties 的值）。

/actuator/flyway
flyway端点提供有关 Flyway 执行的数据库迁移的信息。

/actuator/health 
端点提供有关应用程序运行状况的health详细信息。

/actuator/heapdump
heapdump端点提供来自应用程序 JVM 的堆转储。(通过分析查看/env端点被*号替换到数据的具体值。)

/actuator/httptrace
httptrace端点提供有关 HTTP 请求-响应交换的信息。（包括用户HTTP请求的Cookie数据，会造成Cookie泄露等）。

/actuator/info
info端点提供有关应用程序的一般信息。
```  
  
在/actuator/env直接拿下该账户密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWEtXtYica6uWx6tjTxCuTBYq4ZV7ocF0ZPibWtspfFyQsnfuNJJbmkNHg/640?wx_fmt=png&from=appmsg "")  
  
然后这里直接访问这个下载heapdump文件，然后再使用heapdump工具进行检测里面的敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWMsuSTk0K9eObaOb5LpUqlmOhAYMWnbxq2BM1BCWRibG9OF2ml7JZHvQ/640?wx_fmt=png&from=appmsg "")  
  
使用脚本工具进行分析，里面泄露了很多的信息，可以去里面收集很多的账户密码，然后还有OSS储存桶相关账户信息  
```
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWTYes7SBb7gQ0PoEm6oicBc4nxNIYowrs8q9VUV0XJcguC3eiabHSzXYg/640?wx_fmt=png&from=appmsg "")  
### 漏洞三：api接口未授权访问  
  
这里我利用这个站点直接看里面的js接口，使用findsomething插件看看有什么常见的api泄露的接口，但是在这个插件中没有找到什么有价值的信息泄露接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW6ESXZibnOGxxLIdPBaW4BozwFzDpYMkYiaVE6y7ianicXgicf6NfPklEkSw/640?wx_fmt=png&from=appmsg "")  
  
下面可以尝试F12查看该站点的js文件，看看有没有常见的api泄露接口直接在源代码里面检索文件里面的所有api接口，然后挨个去尝试下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW8JdCawh8Ph60oh0ywZic3TFjCOO1z44YXpMbeeB8T5HcWDb8WAvjP5Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到下面的这个api接口是可以成功访问的，直接一手未授权访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWQ9doWoRiaTyvnFgGTcOPrnsARFwiazykNw0KqXBYFBHiakwjI5zfadFBA/640?wx_fmt=png&from=appmsg "")  
### 漏洞四：Swagger UI信息泄露漏洞  
  
上面泄露的api接口使用Swagger UI插件访问，可以看到下面右下角是没有加密的，也就是我们可以尝试下面的GET、POST请求方法去打一个api接口未授权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWCfsibnUOI2qSLKtVK351dFgpOEYW6mOm0AhN9J6coy2o80CQWvicex6g/640?wx_fmt=png&from=appmsg "")  
  
这里我们可以通过bp爆破去遍历一下id用户信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumW1SGRN0dSDNVhrTq1nibcZYD0feOWV78N709QYE55QLFpu60GASyDfLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWVDOxes7oeibKsKZKX4vxXsVWmSrqvY95MbhKldib3oVOCPxdfG8At8vA/640?wx_fmt=png&from=appmsg "")  
  
然后里面还有很多的这样的信息泄露的接口都可以尝试未授权访问，看看有没有什么敏感信息泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcoicO0zBtSx5UjMA0sr1NumWnaFGcWJ9ibjhW2HM8J9jZIibBJpIkUhrN0GJUkp8tKO2NYuApq3DRhaw/640?wx_fmt=png&from=appmsg "")  
## 0x4 总结  
  
相关的对该目标公司的站点的渗透测试的细节都分享给师傅们了，然后这次的话主要是针对spring-boot的一次横向渗透，利用红队打点的常见思路，对目标站点进行渗透测试，然后再利用别的接口泄露打一套漏洞，最后也是顺利的完成了这次渗透测试的工作。希望这篇文章对师傅们有帮助！！！  
```
```  
  
  
