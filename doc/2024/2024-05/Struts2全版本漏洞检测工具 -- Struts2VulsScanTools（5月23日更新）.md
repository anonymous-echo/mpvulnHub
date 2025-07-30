#  Struts2全版本漏洞检测工具 -- Struts2VulsScanTools（5月23日更新）   
abc123info  Web安全工具库   2024-05-24 22:02  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
Struts2全版本漏洞检测工具。最新更新的部分漏洞：  
```
2024.05.23 解决S2-045-2检测payload极端情况下误报问题。

2023.07.30 解决mac系统兼容性问题，解决软件界面在不同jdk下大小显示不一样问题。

2023.07.20 对每一个文本输入框添加右键撤销功能。

2023.07.19 对所有文本框输入框添加右键复制、粘贴、全选、删除功能。解决Mac系统的兼容性问题。

2023.02.18 新增一条检测Struts2调试模式的语句。
```  
  
0x02 安装与使用  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibt6faJVfBVSRNjBPG7QtXDQk4DmhxPQySY6gw7BAOYyJPGGVBQry1Tkr5W6xzfMA7fbTRUaMbhmYg/640?wx_fmt=png&from=appmsg "")  
  
1、点击“检测漏洞”，会自动检测该URL是否存在S2-001、S2-005、S2-009、S2-013、S2-016、S2-019、S2-020/021、S2-032、S2-037、DevMode、S2-045/046、S2-052、S2-048、S2-053、S2-057、S2-061、S2相关log4j2十余种漏洞。  
  
2、“批量验证”，（为防止批量geshell，此功能已经删除，并不再开发）。  
  
3、S2-020、S2-021仅提供漏洞扫描功能，因漏洞利用exp很大几率造成网站访问异常，本程序暂不提供。  
  
4、对于需要登录的页面，请勾选“设置全局Cookie值”，并填好相应的Cookie，程序每次发包都会带上Cookie。  
  
5、作者对不同的struts2漏洞测试语句做了大量修改，执行命令、上传功能已经能通用。  
  
6、支持GET、POST、UPLOAD三种请求方法，您可以自由选择。（UPLOAD为Multi-Part方式提交）  
  
7、部分漏洞测试支持UTF-8、GB2312、GBK编码转换。  
  
8、每次操作都启用一个线程，防止界面卡死。  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：  
https://pan.quark.cn/s/ee621698b546  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/8H1dCzib3Uibt6faJVfBVSRNjBPG7QtXDQVJRTjILwLHwvYO2tMVibmclMibmSFmms3Zt2fibY663hmqRL79cQZqpdA/640?wx_fmt=jpeg&from=appmsg "")  
  
京东购买链接：https://item.jd.com/14161411.html  
> 本书共20章，分为4篇。第1篇“Linux网络开发基础知识”，涵盖Linux操作系统概述、Linux编程环境、文件系统概述，以及程序、进程和线程等相关知识；第2篇“Linux用户层网络编程”，涵盖TCP/IP族概述、应用层网络服务程序概述、TCP网络编程基础知识、服务器和客户端信息获取、数据的I/O及其复用、基于UDP接收和发送数据、高级套接字、套接字选项、原始套接字、服务器模型、IPv6基础知识等；第3篇“Linux内核网络编程”，涵盖Linux内核层网络架构和netfilter框架的报文处理；第4篇“综合案例”，介绍3个网络编程综合案例的实现，包括一个简单的Web服务器SHTTPD的实现、一个简单的网络协议栈SIP的实现和一个简单的防火墙SIPFW的实现。  
  
  
  
