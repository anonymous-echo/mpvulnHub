#  【漏洞通告】Apache Traffic Control SQL注入漏洞安全风险通告   
 嘉诚安全   2024-12-31 01:31  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache Traffic Control中存在一个SQL注入漏洞，漏洞编号为：  
CVE-2024-45387。  
  
  
Apache Traffic Control（ATC）是一个开源的、基于Web的负载均衡和流量管理解决方案，主要用于管理和配置内容分发网络（CDN）和其他网络流量分发基础设施。Traffic Ops是Apache Traffic Control的核心组件，负责配置、管理和自动化CDN中的各类资源，它提供了基于REST API的接口来管理交付服务、缓存、DNS配置等。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
**PoC/EXP已公开**  
。由于Apache Traffic Control的Traffic Ops组件中未对输入进行充分验证或过滤，具有特定角色（如admin、federation、operations、portal、steering）的特权用户可通过向deliveryservice_request_comments端点发送特制的PUT请求，利用SQL注入漏洞执行任意SQL查询，从而可能泄露、修改或删除数据库中的数据。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Apache Traffic Control 8.0.0 - 8.0.1  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Apache Traffic Control >= 8.0.2  
  
下载链接：  
  
https://trafficcontrol.apache.org/releases/  
  
参考链接：  
  
https://lists.apache.org/thread/t38nk5n7t8w3pb66z7z4pqfzt4443trr  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-45387  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
