#  Apache告警， Struts 2 开源框架存在严重安全漏洞   
小薯条  FreeBuf   2023-12-17 09:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ibje7aEjGmFtq2rWqlQDItWMW6OdFdW2AxDv4HTXuhyGkVTpxBzQhbz4pdgNUHM8s16ibHd56BqlA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
近日，阿帕奇公司发布安全公告称 Struts 2 开源 Web 应用程序框架存在严重安全漏洞，可能导致远程代码执行。  
  
  
该漏洞被追踪为 CVE-2023-50164，其根源在于文件上传逻辑，该逻辑可实现未经授权的路径遍历，在这种情况下极易被用来上传恶意文件并执行任意代码。  
  
  
Shadowserver 扫描平台的研究人员称，已观察到少量黑客参与了漏洞利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ibje7aEjGmFtq2rWqlQDItOr8nh3nvret5O0JSyTPUtfPFU8r6B4X6SMHt7UPTJdwLib6Uiaj1XOoQ/640?wx_fmt=jpeg&from=appmsg "")  
  
【图源：Bleeping Computer】  
  
  
Apache Struts 是一个开源 Web 应用程序框架，旨在简化 Java EE Web 应用程序的开发，提供基于表单的界面和广泛的集成功能。  
  
  
该产品广泛用于私营和公共部门（包括政府组织）的各个行业，因为它可以有效地构建可扩展、可靠且易于维护的 Web 应用程序。  
  
  
此次的漏洞可能允许攻击者上传恶意文件，并在目标服务器上实现远程代码执行 （RCE）。黑客一旦成功利用此类漏洞，就可以修改敏感文件、窃取数据、中断关键服务等。  
  
  
Source Incite 的 Steven Seeley 发现并报告了这一漏洞，此漏洞可能影响以下几个软件版本：  
  
- Struts 2.3.37（EOL）  
  
- Struts 2.5.0 - Struts 2.5.32  
  
- Struts 6.0.0 - Struts 6.3.0  
  
其中，2.5.33 和 6.3.0.2 或更高版本中提供了该漏洞的补丁。  
  
  
阿帕奇公司表示非常感谢 Source Incite 的 Steven Seeley 报告了该漏洞。此外，研究人员强烈建议所有 Struts 2 用户立即安装补丁，并更新到最新的网络应用程序框架版本。并表示这是一个即插即用的替换程序，升级十分便捷。  
  
  
**思科可能受到影响**  
  
  
## 思科在本周二（12月12日）发布的安全公告中表示正在调查 CVE-2023-50164，继而确定哪些采用 Apache Struts 的产品可能受到影响，以及受影响的程度。  
  
  
接受分析的思科产品包括客户协作平台（Customer Collaboration Platform）、身份服务引擎（ISE）、Nexus Dashboard Fabric Controller（NDFC）、统一通信管理器（Unified CM）、统一联络中心企业版（Unified CCE）和 Prime Infrastructure。  
  
  
可能受影响产品的完整列表可在思科的安全公告中找到，该公告预计将根据最新信息进行更新。  
  
  
**风险和潜在影响**  
  
  
## 由于此漏洞允许任意远程代码执行，一旦被成功利用，可能对使用 Struts 2 构建的 Web 应用程序的安全性构成严重风险。  
  
  
攻击者可能会破坏受影响的服务器和网络、执行拒绝服务攻击、窃取敏感数据或使用受感染的系统进行恶意软件分发和其他网络攻击。  
  
  
虽然目前还没有出现黑客利用此漏洞攻击的事件，但不能掉以轻心。该软件之前的一个安全漏洞（CVE-2017-5638，CVSS 得分：10.0）曾在 2017 年被黑客利用，并入侵了美国消费者信用报告机构 Equifax。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7VjpicfRmENW5Jzf1ec8Vub5ibnEQjSlchNRoD5fZNeib09msyqNeZjbWQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
https://thehackernews.com/2023/12/new-critical-rce-vulnerability.html  
  
https://www.bleepingcomputer.com/news/security/hackers-are-exploiting-critical-apache-struts-flaw-using-public-poc/  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7rv5uiamoibTdp9P2ia0swfbiaV4uicHc9icqdtbRUlvMtLfRyDXHqJkQqfBg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491557&idx=1&sn=25a978c3877189a9200d98d85f6db40a&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491574&idx=1&sn=bbc0bfc9c9fb36cceb48abe51520e544&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491557&idx=1&sn=25a978c3877189a9200d98d85f6db40a&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491523&idx=1&sn=ec31589bf31dbe9fdc2b9e4db5321dcc&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247491509&idx=1&sn=358062ec395fbcbe7b15c7c582631a5c&chksm=ce1ce52af96b6c3c9327439b4a74887b00d10c169601c2e26e79ac4105725a9559a908f64390&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
