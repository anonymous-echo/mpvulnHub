#  Apache Parquet Java 中存在CVSS满分漏洞   
do son  代码卫士   2025-04-02 18:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**与列存储相关的开源数据文件格式 Apache Parquet 中被指存在一个严重漏洞，为使用 Apache Parquet Java 库的系统造成严重风险。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMR9o8F57aUB6aUdcCDTmicibwPdsxttmjmMShPnfmzibYbGn9v7pJOVic82cwDZr0lUUbbeYmxZXYyaIQ/640?wx_fmt=png&from=appmsg "")  
  
  
Apache Parquet 为有效存储和检索数据而设计，因高性能的压缩和解码计划而为人所知，适用于批量处理复杂数据。支持多种编程语言和分析工具的性能助力其广泛应用。  
  
该严重的任意代码执行漏洞位于 Apache Parquet Java 库中，编号为CVE-2025-30065，CVSS评分为10分。它具体位于parquet-avro 模块中，当从 Parquet 文件元数据中读取 Avro 结构时，可允许任意代码执行。该漏洞影响 Apache Parquet Java 1.15.0及之前版本。漏洞如遭利用，可导致攻击者完全控制受影响系统、窃取敏感数据、安装恶意软件以及破坏服务。  
  
强烈建议用户尽快升级至已修复该漏洞的1.15.1版本。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Apache Ignite 严重漏洞可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522291&idx=2&sn=d8279f609eb439d7d723557c865748fe&scene=21#wechat_redirect)  
  
  
[Apache MINA 存在严重的满分漏洞，可导致RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521918&idx=1&sn=acf8324d4a36ec4e8d37b16375da9e75&scene=21#wechat_redirect)  
  
  
[Apache Traffic Control存在严重的SQL注入漏洞，可在数据库中执行任意命令](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521906&idx=1&sn=9cb8ea9b9dbfb2a32eec80f9973d8cf1&scene=21#wechat_redirect)  
  
  
[Apache Tomcat 漏洞导致服务器易受RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521893&idx=1&sn=867f98595849107577a98fcaf043a177&scene=21#wechat_redirect)  
  
  
[Apache修复 Struts 2 中的严重 RCE 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521787&idx=1&sn=aa7443d590ca0182f0cbd4386c81152a&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/cve-2025-300  
65-cvss-10-critical-vulnerability-discovered-in-apache-parquet-java/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
