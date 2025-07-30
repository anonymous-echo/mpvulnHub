#  【漏洞通告】DataEase远程代码执行漏洞安全风险通告   
 嘉诚安全   2025-06-05 08:42  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
DataEase远程代码执行漏洞，漏洞编号为：  
CVE-2025-48999、CVE-2025-49001、CVE-2025-49002  
。  
  
  
DataEase是一款开源的数据分析平台，提供丰富的数据可视化和分析功能，帮助用户轻松地进行数据探索和决策支持。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，POC/EXP  
**已公开，**  
技术细节状态**已公开**  
。  
  
CVE-2025-48999为后台Redshift数据源JDBC漏洞，拥有后台权限的攻击者可通过该漏洞执行任意Java代码，从而获取服务器权限。  
  
CVE-2025-49002为后台H2数据源JDBC漏洞，拥有后台权限的攻击者可通过该漏洞执行任意Java代码，从而获取服务器权限。  
  
CVE-2025-49001为权限绕过漏洞，由于JWT鉴权逻辑缺陷，在密钥验证失败的情况下，未停止流程，仍进入到目标函数，导致攻击者可伪造JWT密钥，绕过鉴权。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
DataEase < 2.10.10  
  
**处置建议**  
  
  
  
  
  
  
  
  
官方修复方案：  
  
DataEase官方已发布修复版本，请尽快更新至2.10.10及以上版本 ：  
  
https://github.com/dataease/dataease/security/advisories/GHSA-6pq2-6q8x-mp2r  
  
https://github.com/dataease/dataease/security/advisories/GHSA-999m-jv2p-5h34  
  
https://github.com/dataease/dataease/security/advisories/GHSA-xx2m-gmwg-mf3r  
  
临时缓解措施：  
  
1.通过防护类设备进行防护，拦截请求中出现的恶意Jdbc特征。  
  
2.在不影响业务的情况下，限制设备出网。  
  
3.如非必要，避免将资产暴露在互联网。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
