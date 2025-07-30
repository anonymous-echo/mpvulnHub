#  警惕！PBot挖矿僵尸网络正利用新漏洞发起攻击   
原创 360CERT  三六零CERT   2022-06-24 17:32  
  
**赶紧点击上方话题进行订阅吧！**  
  
报告编号：B6-2022-062402  
  
报告来源：360CERT  
  
报告作者：360CERT  
  
更新日期：2022-06-24  
  
1  
  
 概述  
  
  
  
  
近期，360安全大脑监测到一个挖矿僵尸网络，并对其进行了持续跟踪。其bot模块为GitHub开源的IRCBot（采用Perl语言编写），且病毒脚本中包含perlbot关键字，遂命名为**PBot**。该僵尸网络正利用**Spring4Shell漏洞（CVE-2022-22965）、GitLab CE/EE RCE漏洞（CVE-2021-22205）**等漏洞大肆攻击互联网中主机以植入恶意脚本构建僵尸网络、挖矿牟利。目前该病毒家族至少包含7个漏洞利用模块（详见附录1），并收集了上万个脆弱主机IP地址。  
  
由于上述漏洞均为高危漏洞，利用方式较为简单且已经公开（通过构造恶意HTTP请求即可实现），广大用户可使用360安全大脑相关产品进行全面查杀，并从以下4个方面进行加固，以免遭受黑客攻击，造成不必要的损失。  
```
```  
  
  
2  
  
 漏洞详情  
  
  
  
  
### Spring4Shell漏洞（CVE-2022-22965）  
  
Spring框架是Java平台一个开源的全栈应用程序框架和控制反转容器实现，其参数绑定机制允许开发人员将HTTP 请求详细信息绑定到特定于应用程序的对象。因其getCachedIntrospectionResults方法在绑定参数时错误的暴露了类对象，致使在JDK 9+上运行的Spring MVC、Spring WebFlux应用程序可能容易受到通过参数绑定的远程代码执行 (RCE) 攻击。  
  
漏洞状态：  
<table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">漏洞编号</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">漏洞等级</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;"><strong>漏洞详情</strong></th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;"><strong>POC</strong></th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;"><strong>EXP</strong></th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;"><strong>在野利用</strong></th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">CVE-2022-22965</td><td style="text-align: center !important;">高危</td><td style="text-align: center !important;">已公开</td><td style="text-align: center !important;">已知</td><td style="text-align: center !important;">已知</td><td style="text-align: center !important;">已存在</td></tr></tbody></table><table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">受影响版本</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">安全版本</th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Spring Framework &lt; 5.2.20</td><td style="text-align: center !important;">Spring Framework = 5.2.20</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Spring Framework &lt; 5.3.18</td><td style="text-align: center !important;">Spring Framework = 5.3.18</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Spring Boot &lt; 2.5.12</td><td style="text-align: center !important;">Spring Boot = 2.5.12</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Spring Boot &lt; 2.6.6</td><td style="text-align: center !important;">Spring Boot = 2.6.6</td></tr></tbody></table>  
  
3  
  
 技术分析  
  
  
  
  
### 执行流程  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdAmo7HEeFQlBRkB0HNxAnTxh0sAGtia92xK8VgA7ibkhIJXL3Nv3u9U6Q/640 "")  
  
1）攻击者首先利用Spring4Shell漏洞（CVE-2022-22965）、GitLab CE/EE RCE漏洞（CVE-2021-22205）向存在上述漏洞的主机植入恶意脚本jui.sh（下载挖矿脚本等）、僵尸网络bot模块j（Perl编写）、lans（下载ssh暴破模块）。其利用Spring4Shell（CVE-2022-22965）下载并执行僵尸网络bot模块j的payload片段如下：  
```
```  
  
其次，攻击者还可利用Laravel反序列化RCE漏洞 (CVE-2018-15133)下载并执行僵尸网络bot模块pp。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdyLxuIqZIja0858fT0ibXXJgYqNMqP0HWlx5sjLXwdJW650LYs4ult8w/640 "")  
  
2）接着，恶意脚本jui.sh会下载并运行僵尸网络bot模块lan（Perl编写）构建僵尸网络；然后，执行挖矿shell脚本45.647.txt挖矿牟利。需要注意的是，PBot包含的多个僵尸网络bot模块，只是bot server不同，功能完全一致。  
```
```  
  
3）SSH暴破实现横向传播  
  
恶意脚本lans会从C2（89.44.9.246）下载lan.jpg(一个压缩包)，其目录结构如下：  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdCtS4j7mC0Kj16OMiaXvWTrgj13rAAafnrBwktVgo5ZbwFQ4HQfOhmJg/640 "")  
  
首先，恶意脚本run调用恶意elf文件pass，获取中招主机所有用户名，生成新的暴破字典保存到pass.txt，并与原始暴破字典passfile合并，以生成最终的暴破字典pass3。最后，调用恶意脚本c对主机所在网段进行SSH暴破。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60Fd5FETr4FwB5k4oqIOVvIGibB8z5Ub0uY37f4F3HDMWicQHj9ZTAJbImlw/640 "")  
  
SSH暴破成功后，便执行shell命令以下载并运行Perl编写的僵尸网络bot模块pp。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdBJPpwEkX2icmwibibiaiaZq6cFc18FiaRWbBf4e85GmoSaaSyGPRib1ldyfbw/640 "")  
  
其中，cola是一个用于暴破的黑客工具。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdEvM5ZutumXicEic8Yf8Dt8wBj35Umx2YJcPaOCp2jS4ugDOOiajbicic1RQ/640 "")  
### 僵尸网络bot模块  
  
bot模块可对目标主机发起多种DDoS攻击，支持近40条指令（含7条DDoS攻击指令、6条洪泛攻击指令），详细指令详见附录2。其通信过程大致如下：  
  
1）TCP连接建立后，中招主机使用IRC协议向bot server（194.163.141.243:6667）发送2个请求，进行身份验证。其中BU-57890为中招主机昵称标识（格式为："BU-" + rand(99999) ）。  
```
```  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdAVsGTnk7VawatUncmLibAtNoImO2HSic70JroQdTcvcvhmR6vZn2XrJA/640 "")  
  
2）中招主机身份验证通过后，bot server会发送欢迎信息，并告知中招主机当前僵尸网络结点个数等信息。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60Fd0l3FA5kENMaqibVq9SNllHicCgftwy77V4jHbcqZFIjia4JmZRXdxRHkw/640 "")  
  
3）接着，中招主机发送加入僵尸网络请求（JOIN指令）；bot server将其加入僵尸网络，并告知当前僵尸网络中已有结点昵称。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdKyqwicxFuichckUGZqtMqNogU3GYGPEU29XHmOKo4BolmyvPRUNhYlTA/640 "")  
  
4）当有新的结点加入该僵尸网络时，bot server会告知中招主机。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdXOHptM2Lt2Wtu4PYSic4Mamdn7YyVF0W5IsNsC0I8oCAQ5Hr9gBjiaibw/640 "")  
### 门罗币挖矿  
  
恶意shell脚本45.647.txt，主要功能为：  
  
1）创建目录  
```
```  
  
2）清除其他挖矿对手  
  
3）创建下载恶意shell脚本ioi的定时任务，ioi脚本又会从C2（89.44.9.246）下载45.647.txt，从而实现持久化。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdUUTgvwsRpANgPibHKQMtVof4crmGg7roddu9YZ7E0h6VaIicek7Xdniag/640 "")  
  
4）下载并运行xmrig挖矿木马  
  
为了增强挖矿活动隐蔽性，其会自动结束CPU占用率70%以上的进程。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdUicHDP4c1icQF3pFRDkJEhWpMbv0ECx9pqgkt9xGW5aW7qCKnpntKicbQ/640 "")  
  
同时，我们注意到，其早期挖矿模块xmr.tgz，则采用伪装进程名方式隐蔽挖矿，并通过添加挖矿启动脚本定时任务方式实现持久化。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60Fdxn8XrmpfSCnULuZGKoTNksQDJoHOE4NVgLklr0oFqKdrQeYva4FHrg/640 "")  
  
如下是PBot其中一个钱包地址的收益情况，对应公共矿池94.130.13.27:7777（pool.supportxmr.com）。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60Fder2BplWZQLuNZPhtvvA5sB9eCDHwq9z2k3ItJ49a8AUowGMjzYAkcQ/640 "")  
  
最新版的矿池为：sshd1.psybnc.org:4430，可以发现其从公共矿池到私有矿池的转变。  
### 顺藤摸瓜  
  
在对该僵尸网络进行深入挖掘溯源后，我们还原了其大致架构。  
<table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">目录名</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">备注</th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">/22</td><td style="text-align: center !important;">漏洞利用相关文件，以及扫描的目标IP列表</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">/all</td><td style="text-align: center !important;">恶意主脚本、挖矿相关文件、扫描的目标IP列表</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">根目录下的其他文件</td><td style="text-align: center !important;">bot模块（perl脚本）、ssh暴破模块、扫描的目标IP列表、其他恶意脚本</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">/znc</td><td style="text-align: center !important;">挖矿相关文件</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">/v5</td><td style="text-align: center !important;">无访问权限</td></tr></tbody></table>![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60Fdf2ZwtLgp4AnyGnSz1Qkz2PySyKXibzClKSBl5VTAxE96N7pWdPVxEUA/640 "")  
  
  
4  
  
 **IoCs**  
  
  
  
  
**C2:**  
  
89.44.9.246  
  
146.70.80.113  
  
185.158.251.99  
  
194.163.141.243  
  
ftp.neitel.net  
  
**矿池：**  
  
94.130.13.27:7777  
  
sshd1.psybnc.org:4430  
  
gulf.moneroocean.stream:10128  
  
**钱包地址：**  
  
42Q8pHgf7tKTB7u1Lv6kmFRCg24udi2prGZ5gP2GUioiDL2sbgAag3Y9AWsQrDJSg991pU6keY1RqRSYTPCEWrhrV65W3qY  
  
87CgVNisfTySvd79TSEqYWcRyzkSUJx2i5YJP9mx9R2QPVsD8HG3Rb2abSHbcHteYoHdWmx6Y9QvA8FPxzHDo2wE55K3iqv  
<table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">MD5</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">文件名</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">文件类型</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">备注</th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">851391be5d17a58dfaaf53172f3b2b1c</td><td style="text-align: center !important;">jui.sh</td><td style="text-align: center !important;">shell</td><td style="text-align: center !important;">首个入侵的恶意shell脚本</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">7962743968b186b082c0aa66c838f284</td><td style="text-align: center !important;">45.647.txt</td><td style="text-align: center !important;">shell</td><td style="text-align: center !important;">第二阶段下载的挖矿shell脚本</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">58d7aaf6a4152585d5453de0b1797daf</td><td style="text-align: center !important;">lan</td><td style="text-align: center !important;">perl</td><td style="text-align: center !important;">perl编写的bot</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">bc5ef4ef66a24188056c17631ed1da77</td><td style="text-align: center !important;">j</td><td style="text-align: center !important;">perl</td><td style="text-align: center !important;">perl编写的bot</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">bc485470f634c659e68fbb18b1f92970</td><td style="text-align: center !important;">pp</td><td style="text-align: center !important;">perl</td><td style="text-align: center !important;">perl编写的bot</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">dc3f6b91e39ebb6b2f2642039025d0bd</td><td style="text-align: center !important;">ioi</td><td style="text-align: center !important;">shell</td><td style="text-align: center !important;">下载45.647.txt的恶意shell脚本</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">c57ff21ebf088948ec05ac7dd89826dd</td><td style="text-align: center !important;">45.64.rar</td><td style="text-align: center !important;">elf</td><td style="text-align: center !important;">xmrig挖矿木马</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">ea9dc6a4690b3dd511f8c7d58003774d</td><td style="text-align: center !important;">45.64.json</td><td style="text-align: center !important;">json</td><td style="text-align: center !important;">挖矿配置文件</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">acb42ee232214fbe14f463584964cd11</td><td style="text-align: center !important;">xmr.tgz</td><td style="text-align: center !important;">tgz</td><td style="text-align: center !important;">挖矿模块</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">333be948f8c195e5fdcde7110bf3f2d5</td><td style="text-align: center !important;">lans</td><td style="text-align: center !important;">shell</td><td style="text-align: center !important;">下载ssh暴破模块lan.jpg</td></tr></tbody></table>  
  
5  
  
 附录  
  
  
  
  
附录1：该病毒家族用到的7个漏洞  
<table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">漏洞名称</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">漏洞编号</th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Spring4Shell漏洞</td><td style="text-align: center !important;">CVE-2022-22965</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">GitLab CE/EE RCE漏洞</td><td style="text-align: center !important;">CVE-2021-22205</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Linux Polkit权限提升漏洞</td><td style="text-align: center !important;">CVE-2021-4034</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Linux内核提权漏洞</td><td style="text-align: center !important;">CVE-2021-3493</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Sudo 堆缓冲区溢出漏洞</td><td style="text-align: center !important;">CVE-2021-3156</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">Laravel 反序列化RCE漏洞</td><td style="text-align: center !important;">CVE-2018-15133</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">脏牛漏洞（dirtycow）</td><td style="text-align: center !important;">CVE-2016-5195</td></tr></tbody></table>  
附录2：Bot模块指令  
<table><tbody style="margin: 0px;padding: 0px;border-width: 0px;border-style: initial;border-color: initial;"><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">指令类型</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">指令名</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">条数</th><th style="font-size: 12px;border-width: 1px;border-style: solid;border-color: rgb(204, 204, 204);margin: 0px;padding: 0.5em 1em;word-break: unset;">具体指令</th></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">DDoS攻击指令</td><td style="text-align: center !important;">ddos</td><td style="text-align: center !important;">7</td><td style="text-align: center !important;">udpflood<host><packet size="size"><time><br/>udp<host><port><packet size="size"><time><br/>tcpflood<host><port><packet size="size"><time><br/>httpflood<host><time><br/>sqlflood<host><time><br/>syn<destip><destport><time in="in" seconds="seconds"><br/>sudp<host><port><reflection file="file"><threads><time></time></threads></reflection></port></host></time></destport></destip></time></host></time></host></time></packet></port></host></time></packet></port></host></time></packet></host></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">洪泛攻击指令</td><td style="text-align: center !important;">flooding</td><td style="text-align: center !important;">6</td><td style="text-align: center !important;">msgflood<who><br/>dunixflood<who><br/>ctcpflood<who><br/>noticeflood<who><br/>channelflood<br/>maxiflood<who></who></who></who></who></who></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">数据流及漏洞更新指令</td><td style="text-align: center !important;">news</td><td style="text-align: center !important;">2</td><td style="text-align: center !important;">packetstorm<br/>milw0rm</td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">黑客攻击相关指令</td><td style="text-align: center !important;">hacking</td><td style="text-align: center !important;">12</td><td style="text-align: center !important;">multiscan<vuln><dork><br/>socks5<br/>portscan<ip><br/>logcleaner<br/>sendmail<subject><sender><recipient><message><br/>system<br/>cleartmp<br/>unixable<br/>nmap<ip><beginport><endport><br/>back<ip><port><br/>linuxhelp<br/>cd tmp</port></ip></endport></beginport></ip></message></recipient></sender></subject></ip></dork></vuln></td></tr><tr style="border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;margin: 0px;padding: 0px;"><td style="text-align: center !important;">IRC通信相关指令</td><td style="text-align: center !important;">irc</td><td style="text-align: center !important;">12</td><td style="text-align: center !important;">killme<br/>join #channel<br/>part #channel<br/>reset<br/>voice<who><br/>owner<who><br/>deowner<who><br/>devoice<who><br/>halfop<who><br/>dehalfop<who><br/>op<who><br/>deop<who></who></who></who></who></who></who></who></who></td></tr></tbody></table>  
  
6  
  
 产品侧解决方案  
  
  
  
  
若想了解更多产品信息或有相关业务需求，可移步至http://360.net。  
### 360安全分析响应平台  
  
360安全大脑的安全分析响应平台通过网络流量检测、多传感器数据融合关联分析手段，对该类漏洞的利用进行实时检测和阻断，请用户联系相关产品区域负责人获取对应产品。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ic3Rgfdm96cnvL1JNTRV9WhygTAlKPQib5cvHUGAOPwlj7GK3xQES2M9nfbFbaDzmESibY9sZpngYCRw3HjZ80OQ/640 "")  
### 360安全卫士  
  
Windows用户可通过360安全卫士实现对应补丁安装、漏洞修复、恶意软件查杀，其他平台的用户可以根据修复建议列表中的安全建议进行安全维护。  
  
360CERT建议广大用户使用360安全卫士定期对设备进行安全检测，以做好资产自查以及防护工作。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96cnvL1JNTRV9WhygTAlKPQibsfKZIBEWrtGa66w4bTgg7Jve4SJ7XCgTbqnrAf76q59p0KDlpVjndw/640 "")  
### 360本地安全大脑  
  
360本地安全大脑是将360云端安全大脑核心能力本地化部署的一套开放式全场景安全运营平台，实现安全态势、监控、分析、溯源、研判、响应、管理的智能化安全运营赋能。360本地安全大脑已支持对相关漏洞利用的检测，请及时更新网络神经元（探针）规则和本地安全大脑关联分析规则，做好防护。  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ic3Rgfdm96eJtWkY4Iq9DIVuxSCmNG3Kk2Tz1u8lSQqX1rw7Zia51p6WaILL9xBHMFtUXVj2BG13gviadr8dpGcA/640 "")  
### 360终端安全管理系统  
  
360终端安全管理系统软件是在360安全大脑极智赋能下，以大数据、云计算等新技术为支撑，以可靠服务为保障，集防病毒与终端安全管控功能于一体的企业级安全产品。  
  
360终端安全管理系统已支持对相关漏洞进行检测和修复，建议用户及时更新漏洞库并安装更新相关补丁。  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fzSgCnRhHkrMfT0tzT60FdWWk3XGcvGLiatseAkG3JfQO8ewibaXSAic2Wrrr5gjKGtR1dMCUaWAANA/640 "")  
  
  
7  
  
 时间线  
  
  
  
  
**2022-06-24** 360高级威胁研究分析中心发布通告  
  
8  
  
 特制报告相关说明  
  
  
  
  
一直以来，360CERT对全球重要网络安全事件进行快速通报、应急响应。为更好地为政企用户提供最新漏洞以及信息安全事件的安全通告服务，现360CERT推出了安全通告特制版报告订阅服务，以便用户做资料留存、传阅研究与查询验证。  
  
今后特制报告将不再提供公开下载，用户可扫描下方二维码进行服务订阅。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ic3Rgfdm96dGuACWTa4BQzhoMl3chI7Tdch7TU5O21ECnPYAkbzMTfjcuvslias51NRldtrfia2XCvoI05Q91X8Q/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fDEiaYRAwzeORXyPTzIZEicJEJchzE6NNx8UKdqTdwDHNIYmwsIK7JlquzGrjaQS7ssnemOGtsTvYw/640?wx_fmt=png "")  
  
360CERT  
https://cert.360.cn/  
  
进入官网查看更多资讯  
  
长按扫码关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fDEiaYRAwzeORXyPTzIZEicJJ6oj5eUnvicLHzb45xcpgT8bhs83yg8VQjlRo8Av3jvfEv1NNMfHvRA/640 "微信公众号二维码.jpg")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ic3Rgfdm96fDEiaYRAwzeORXyPTzIZEicJLRf9N0If8jPYhCicZ5sao1dWa48hVm5xpUskBUnDMYmvTJHpsWTmBsw/640?wx_fmt=png "")  
  
点击在看，进行分享  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ic3Rgfdm96fDEiaYRAwzeORXyPTzIZEicJX2oU8HWWic5QdjaCkRHBK3anwULoleLibhW5SnibSGWCF1fjkYS5ia8JPg/640?wx_fmt=gif "")  
  
