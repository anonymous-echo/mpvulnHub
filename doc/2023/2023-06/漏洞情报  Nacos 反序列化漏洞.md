#  漏洞情报 | Nacos 反序列化漏洞   
 斗象智能安全   2023-06-08 16:37  
  
**1.1  漏洞概述**  
  
  
  
  
近日，斗象科技漏洞情报中心监控到公网公开披露了Nacos 反序列化漏洞，未经身份验证的攻击者可以通过hessian反序列化进行RCE利用。  
  
Nacos是一款开源的分布式服务发现和配置管理平台，用于帮助用户实现动态服务发现、服务配置管理、服务元数据及流量管理等功能。该漏洞仅影响7848端口（默认设置下），一般使用时该端口为Nacos集群间Raft协议的通信端口，不承载客户端请求，如部署时已进行限制或未暴露，则风险可控，建议客户做好自查及防护。  
  
**1.2  影响范围**  
  
  
  
  
1.4.0 <= Nacos < 1.4.6  
  
2.0.0 <= Nacos < 2.2.3  
  
**1.3  复现环境**  
  
  
  
  
JDK 8u191  
  
Nacos 2.2.2  
  
**1.4  漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IzoUxlR3uC0gXIlThIqdhvdFJjiatib4rsKwt6gqA9xeqqnt1fzpPLmjMoqicfRMTF565ic1n1PTka7ltqialg9lAlg/640?wx_fmt=png "")  
  
**1.5  修复建议**  
  
  
  
  
**>> 1.5.1  版本升级**  
  
  
  
  
厂商已发布了漏洞修复程序，请使用此产品的用户尽快更新至安全版本：  
  
Nacos 1.4.6  
  
Nacos 2.2.3   
  
官方下载链接：  
  
https://github.com/alibaba/nacos/releases  
  
斗象情报中心补丁站下载链接：  
  
https://vip.tophant.com/patch?keyword=/Nacos/Nacos 反序列化漏洞  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/IzoUxlR3uC2JN3JhnHAqW9gyCB6ytWABqTPbuvibGW8hcCQs3lWclfic4urI6cQp9p0ljjGy1WrA8BuAIoVLutiaA/640?wx_fmt=gif "")  
  
[](http://mp.weixin.qq.com/s?__biz=MzIwMjcyNzA5Mw==&mid=2247490829&idx=1&sn=033de9cd524edf003a53b59811306eb0&chksm=96db16d7a1ac9fc1a438e8567ae793c3d4e66af17ef15170aac88e5f73f70946ff1e2de5cc4b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzIwMjcyNzA5Mw==&mid=2247490504&idx=1&sn=e96af5f28fe8e43cadc87b9a5e77e5d4&chksm=96db1012a1ac9904bbb25c43e1f28a68545c60f0c4f621348320e21d0150e646106723e35d1c&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzIwMjcyNzA5Mw==&mid=2247490490&idx=1&sn=fd53d0a05cfea5787c1e07c1dfb37520&chksm=96db1060a1ac99762bcce2b9c902d25d274201fa3887ba11c2a0a74d49aff5f3208f3c4e96a2&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/IzoUxlR3uC3VT5T84OIlPJSPEtehpb7k1LNWlE9NP18iaO9ZFv3JgFMEk5KictJl6DqsHB5w6HYdOqAMOVFNeTUg/640?wx_fmt=gif "")  
  
