#  Mesh Wi-Fi存在CVSS 9.1分高危漏洞，设计缺陷可被用于数据帧注入攻击   
FreeBuf  FreeBuf   2025-05-27 11:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![Mesh Wi-Fi漏洞：A-MSDU欺骗攻击示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iccVtiaSzLOdiaOWSeZ0SmRIqNvicR7bZK5uVQPpEgNxjYfXm66VS2yey6Tj1QRphzjJvicWRDxxgS7BA/640?wx_fmt=jpeg&from=appmsg "")  
  
### Part01  
### 漏洞概述  
  
  
研究人员发现主流Mesh Wi-Fi系统中存在一个关键设计缺陷（CVSS评分9.1），攻击者可利用该漏洞实施A-MSDU（聚合MAC服务数据单元）欺骗攻击，实现无线数据帧注入。目前已有概念验证（PoC）代码公开。  
  
### Part02  
### 技术背景  
  
  
该漏洞属于FragAttacks（分段与聚合攻击）类漏洞，影响基于IEEE 802.11协议的Mesh网络架构。攻击者通过构造特制的聚合数据帧，可绕过常规的Wi-Fi安全防护机制。  
  
### Part03  
### 风险提示  
  
- 漏洞允许攻击者在未认证情况下注入恶意数据帧  
  
- 可能引发中间人攻击、网络流量劫持等安全事件  
  
- 受影响设备包括多个主流厂商的Mesh Wi-Fi产品  
  
**参考来源：**  
  
Mesh Wi-Fi Hack (CVSS 9.1): Design Flaw Enables Frame Injection (PoC Available)  
  
https://securityonline.info/mesh-wi-fi-hack-cvss-9-1-design-flaw-enables-frame-injection-poc-available/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651321451&idx=1&sn=5471e9d1f4dd5999849c99d712ba7bd8&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
