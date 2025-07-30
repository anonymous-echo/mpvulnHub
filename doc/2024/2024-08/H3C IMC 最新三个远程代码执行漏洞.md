#  H3C IMC 最新三个远程代码执行漏洞   
原创 SXdysq  南街老友   2024-08-12 20:21  
  
**简介**  
  
H3C iMC智能管理中心是一款基于B/S架构推出的综合网络管理产品。IMC以网络管理为核心，特别强调网络中的各种资源、用户和网络服务。其目标是为网络管理员提供一种集成资源、用户和网络服务的网络管理解决方案，实现对网络的端到端管理。  
  
它融合了当前多个产品，以统一风格提供与网络相关的各类管理、控制、监控等功能；同时以开放的组件化的架构原型，向平台及其承载业务提供分布式、分级式交互管理特性；并未业务软件的下一代产品提供最可靠的、可扩展、高性能的业务平台。  
  
**漏洞说明**  
  
H3C iMC智能管理中心 autoDeploy.xhtml 、index.xhtml、login.jsf三个接口处存在远程代码执行漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。该漏洞利用难度较低，建议受影响的用户尽快修复。  
  
**网络资产**  
```
product="H3C-iMC"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtB4uudZa386ibd4Gct42hc9pH767aFMAudvWzrtEjvzKQB5afYqd1QmFicDD5QYNV2Pxadpw9rxapqQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞路径**  
```
POST /imc/autoDeploy.xhtml;.js HTTP/1.1
```  
  
**漏洞检测与利用**  
目前工具集成漏洞如下：  
```
[+] H3C CVM CAS云计算管理平台前台文件上传
[+] H3C 校园网自助服务系统flexfileupload任意文件上传
[+] H3C IMC dynamiccontent.properties.xhtml反序列化
[+] H3C IMC login.jsf 远程代码执行漏洞
[+] H3C IMC autoDeploy.xhtml 远程代码执行漏洞
[+] H3C IMC index.xhtml 远程代码执行漏洞
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtB4uudZa386ibd4Gct42hc9pIbuhWEGBwGJk52UIMkkPGzO2ibXZp1lYO1q8Cb01lkXT0RxmCmqUiaZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtB4uudZa386ibd4Gct42hc9pZoZcRbNlOs9Z0Nu0pOnLa0icM6tHkWQpUibZRu3b7OQj5xbADwxfwxXA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtB4uudZa386ibd4Gct42hc9pGHibgw7iaIdfaUe4ukEwRFL3fAjj7OPJkckPGh7Ug0WF5GLJO698SOibQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtB4uudZa386ibd4Gct42hc9pwI4RocFpAXejz70XkLWyXG4M3Z1UJiatg0eG2XH2coLfYPFjnib6lcKA/640?wx_fmt=png&from=appmsg "")  
  
**工具获取**  
  
H3C洞检测与利用工具已上传内部圈子，可扫码加入获取。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/dfviaLov8RtB4uudZa386ibd4Gct42hc9piafgnIuLxiby5KtDPNnnlsvn9aqLbug4LY8Wj9FynsgW6NxjTWxibfDyw/640?wx_fmt=jpeg "")  
  
  
**🍻🍻🍻🍻🍻🍻**  
```
生活就像一面镜子，你对它笑，它也会对你笑。
每个不曾起舞的日子，都是对生命的辜负。
在黑暗中寻找光明，即使只是一束微光。
人生没有过不去的坎，只有过不去的心情。
成长就是学会与生活的缺憾和解，并继续前行。
只有经历过风雨，才能看到最美的彩虹。
失败是成功之母，每一次跌倒都是通向胜利的阶梯。
相信自己，你已经比昨天的自己更强大。
梦想不会主动找到你，你必须为它努力奔跑。
不要害怕做梦，梦想是现实的前奏。
有时候，慢一点走反而能走得更远。
勇气不是没有恐惧，而是在恐惧中继续前行。
只要心中有光，世界就不会黑暗。
把握现在，就是创造未来最好的方式。
最好的时光永远是当下，不要让过去或未来困扰你。
```  
  
  
