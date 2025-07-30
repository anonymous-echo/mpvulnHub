#  微软6月补丁日：修复 66 个漏洞，包括一个APT组织利用的0day  
会杀毒的单反狗  军哥网络安全读报   2025-06-11 01:03  
  
**导****读**  
  
  
  
微软六月补丁日更新已发布，微软修复其产品线中的 66 个安全漏洞。其中包括一个在实际攻击中被利用的  
0day  
。  
  
  
We  
b  
DAV（Web 分布式创作和版本控制）漏洞被标记为“重要”，CVSS 评分为 8.8/10，如果目标点击被操纵的网站，则允许基于浏览器的驱动下载。  
  
  
WebDAV 漏洞影响Windows 10 和 Windows 11以及相关的服务器版本。虽然微软尚未披露攻击的全部细节，但他们已确认该漏洞已被广泛利用。  
  
  
微软在一份简报中表示： “WebDAV 中对文件名或路径的外部控制允许未经授权的攻击者通过网络执行代码。”  
  
  
Check Point 将此次  
0day  
野外攻击与一个名为“Stealth Falcon”的 APT 组织联系起来，该组织使用鱼叉式网络钓鱼攻击土耳其、卡塔尔、埃及和也门目标。Stealth Falcon 已被公开归咎于阿联酋。  
  
  
由于 WebDAV 依赖于旧版 MSHTML 和 EdgeHTML 渲染引擎，微软还通过 Internet Explorer 累积更新渠道为旧版服务器平台推送修复程序，确保底层脚本组件与核心 WebDAV 代码一起进行修补。  
  
### 10个关键漏洞  
###   
  
除了  
0  
day  
漏洞外，微软还修补了10个评级为“严重”的漏洞，这通常意味着这些漏洞允许远程执行代码或提升权限，而无需太多用户交互。其中包括Microsoft Office中的四个漏洞，这些漏洞仍然是攻击者通过电子邮件发送恶意文档的常规目标。  
  
  
其他获得修复的产品包括 Microsoft Edge、Power Automate、.NET 以及 Windows 本身的组件。虽然其他问题尚未被报告为被主动利用，但有几个问题被标记为短期内更有可能成为攻击目标。  
  
  
参考微软  
6  
月安全更新指南：  
  
https://msrc.microsoft.com/update-guide/releaseNote/2025-Jun  
  
  
新闻链接：  
  
https://hackread.com/june-2025-patch-tuesday-microsoft-bugs-active-0-day/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
