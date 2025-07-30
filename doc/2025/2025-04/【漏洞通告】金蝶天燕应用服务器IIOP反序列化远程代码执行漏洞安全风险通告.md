#  【漏洞通告】金蝶天燕应用服务器IIOP反序列化远程代码执行漏洞安全风险通告   
 嘉诚安全   2025-04-25 06:28  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
金蝶天燕应用服务器IIOP反序列化远程代码执行漏洞。  
  
  
金蝶Apusic应用服务器（Apusic Application Server，AAS）是一款企业级中间件，全面支持JakartaEE规范，提供Web、EJB、WebService容器，适配国产软硬件，用于支撑企业级应用运行。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，POC\EXP**已公开**  
。  
金蝶天燕应用服务器在处理 IIOP 协议请求时，存在 Java 反序列化漏洞。服务器暴露接口允许远程客户端通过 IIOP 协议进行交互，且服务器未对反序列化数据进行有效验证和过滤，攻击者可以构造恶意的序列化数据并发送到服务器，从而实现远程代码执行。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Apusic 应用服务器软件 V10.0 企业版 SP1-SP8  
  
**处置建议**  
  
  
  
  
  
  
  
  
官方已发布修复版本，建议受影响用户尽快进行下载更新。  
  
https://www.apusic.com/view-477-120.html  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
