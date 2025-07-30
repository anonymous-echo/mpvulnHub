#  Apache Ignite 严重漏洞可导致RCE   
do son  代码卫士   2025-02-20 10:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**用于高性能计算的热门开源分布式数据库 Apache Ignite 中存在一个高危漏洞 (CVE-2024-52577)，CVSS评分为9.5，可导致远程攻击者在易受攻击的 Ignite 服务器上执行任意代码。**  
  
该漏洞影响 Apache Ignite 2.6.0至2.17.0之前的版本，是因为某些Ignite端点的类序列化过滤器处理不当造成的。攻击者可构造包含易受攻击对象的恶意 Ignite 消息并将其发送给可疑服务器，利用该漏洞。  
  
安全公告提到，“Ignite 服务器对此类信息进行反序列化可能导致在 Apache Ignite 服务器端执行任意代码。”它可导致攻击者对受影响系统具有重大控制权限，可能导致数据遭泄露、服务被中断，甚至系统遭完全攻陷。  
  
Apache Ignite 团队已在2.17.0版本中修复该漏洞。强烈建议受影响版本的用户尽快升级至最新版本。依赖于 Apache Ignite 的组织机构和个人应优先应用该必要更新，保护系统免受潜在攻击。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Apache MINA 存在严重的满分漏洞，可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521918&idx=1&sn=acf8324d4a36ec4e8d37b16375da9e75&scene=21#wechat_redirect)  
  
  
[Apache Traffic Control存在严重的SQL注入漏洞，可在数据库中执行任意命令](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521906&idx=1&sn=9cb8ea9b9dbfb2a32eec80f9973d8cf1&scene=21#wechat_redirect)  
  
  
[Apache Tomcat 漏洞导致服务器易受RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521893&idx=1&sn=867f98595849107577a98fcaf043a177&scene=21#wechat_redirect)  
  
  
[Apache修复 Struts 2 中的严重 RCE 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521787&idx=1&sn=aa7443d590ca0182f0cbd4386c81152a&scene=21#wechat_redirect)  
  
  
[Apache Avro SDK 中存在严重漏洞，可导致在 Java 应用中实现RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520994&idx=1&sn=0feb249fd14e6b8b07d5d6531f3287c2&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://securityonline.info/cve-2024-52577-cvss-9-5-apache-ignite-vulnerability-could-allow-remote-code-execution/  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
