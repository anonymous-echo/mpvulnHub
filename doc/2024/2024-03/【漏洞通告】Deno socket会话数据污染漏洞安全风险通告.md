#  【漏洞通告】Deno socket会话数据污染漏洞安全风险通告   
 嘉诚安全   2024-03-27 15:57  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Deno中存在一个socket会话数据污染漏洞，  
漏洞编号为：CVE-2024-27935。  
  
  
Deno是一个开源的，简单、现代且安全的JavaScript和TypeScript运行环境。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**漏洞，源于Node.js兼容性存在问题，在stream_wrap.ts中重用全局缓冲区，导致跨会话数据污染。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
1.35.1 <= Deno < 1.36.3  
  
  
**修复建议**  
  
  
  
  
  
  
  
  
根据影响版本中的信息，建议相关用户尽快更新至安全版本：  
  
Deno >= 1.36.3  
  
参考链接：  
  
https://github.com/denoland/deno/security/advisories/GHSA-wrqv-pf6j-mqjp  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
