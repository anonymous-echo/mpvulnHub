#  【漏洞通告】Tornado日志解析器拒绝服务漏洞安全风险通告   
 嘉诚安全   2025-05-19 02:03  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
Tornado日志解析器拒绝服务漏洞，漏洞编号为：  
CVE-2025-47287  
。  
  
  
Tornado是一个高性能的Web框架和异步网络库，专为处理大规模并发连接设计。它支持非阻塞I/O，能够处理成千上万的连接，适用于实时Web应用程序。Tornado提供了一个简单易用的Web服务器，并支持WebSockets、长轮询等协议，广泛用于构建高效的实时通信系统。它适用于需要高吞吐量和低延迟的场景，如聊天应用、推送通知等。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
Tornado的multipart/form-data解析器在默认启用的情况下，当遇到特定错误时，会记录警告信息并继续解析后续数据。这种处理方式使攻击者能够发送恶意请求，生成大量警告日志，从而消耗系统资源并导致拒绝服务（DoS）攻击。由于Tornado的日志子系统是同步的，漏洞的影响进一步加剧，导致日志处理延迟，进而影响系统性能。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Tornado <= 6.4.2  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级到Tornado 6.5.0版本。  
  
下载链接：  
  
https://github.com/tornadoweb/tornado/tags/  
  
2.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。  
  
加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
3.参考链接  
  
https://github.com/tornadoweb/tornado/tags  
  
https://github.com/tornadoweb/tornado/security/advisories/GHSA-7cx3-6m66-7c5m  
  
https://nvd.nist.gov/vuln/detail/CVE-2025-47287  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
