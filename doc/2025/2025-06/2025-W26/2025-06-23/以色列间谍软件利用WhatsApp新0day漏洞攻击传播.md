> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795507&idx=2&sn=81a8c861f8f003d76e97b754da52a2e9

#  以色列间谍软件利用WhatsApp新0day漏洞攻击传播  
会杀毒的单反狗  军哥网络安全读报   2025-06-23 01:01  
  
**导****读**  
  
  
  
Meta 最近发现一个 FreeType 漏洞（在披露时被标记为可能被利用）与以色列间谍软件 Paragon 的漏洞利用有关。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaFQA7TpicYvyNkicjBMJPNUwWicrTPkxYsL6oRmb1TDC2XvuxJLLwrYO2KG8LciaDYX1mg2wyBdyvL7qQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
3月中旬，Meta在Facebook安全公告页面上发布了一份公告，告知用户FreeType开源库中存在一个越界漏洞CVE-2025-27363 ，该漏洞可能导致任意代码执行。公告指出，该漏洞可能已被利用。  
  
  
5 月初，Android 系统中的该漏洞已得到修补，并被网络安全机构 CISA添加到其已知被利用漏洞 ( KEV ) 目录中。  
  
  
目前还没有关于利用 CVE-2025-27363 进行攻击的公开信息。  
  
  
SecurityWeek本周从 WhatsApp 获悉，在该漏洞与 Paragon 间谍软件关联。  
  
  
多伦多大学公民实验室研究小组今年3月报告称，WhatsApp的一个  
0day  
漏洞已被Paragon间谍软件攻击所利用。WhatsApp表示，这些  
0day  
攻击涉及使用群组和发送PDF文件，并且该漏洞已在服务器端得到修补，无需在客户端进行修复。  
  
  
WhatsApp 现已透露，CVE-2025-27363 是在对 WhatsApp 之外的其他潜在渠道进行  
  
调查时发现的，间谍软件公司等威胁组织可能正在使用这些渠道传播恶意软件。  
  
  
WhatsApp 表示，它与其他机构分享了调查结果，以帮助加强整个行业的防御能力。  
  
  
FreeType 是一个用于将文本渲染到位图上的开发库，并提供对其他字体相关操作的支持。就 CVE-2025-27363 漏洞而言，该漏洞影响 FreeType 2.13.0 及更早版本，Meta 表示，该漏洞是在“尝试解析与 TrueType GX 和可变字体文件相关的字体子字形结构”时触发的。  
  
  
Meta 在其安全公告中解释道：“该漏洞代码将一个有符号短整型值赋值给一个无符号长整型值，然后添加一个静态值，导致其回绕并分配过小的堆缓冲区。之后，该代码会将最多 6 个有符号长整型值写入超出该缓冲区边界的位置。” “这可能导致任意代码执行。”  
  
  
公民实验室发现证据表明，Paragon 的 Graphite 间谍软件已被澳大利亚、加拿大、丹麦、意大利、塞浦路斯、新加坡和以色列等国家使用。  
  
  
Paragon 以开发无需目标用户任何交互的  
0  
点击漏洞利用而闻名。公民实验室发现，有迹象表明该公司直到最近才能够入侵最新款 iPhone。苹果公司现已修复了被利用的漏洞。   
  
  
漏洞公告：  
  
https://www.facebook.com/security/advisories/cve-2025-27363  
  
公民实验室的调查报告：  
  
https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/  
  
  
新闻链接：  
  
https://www.securityweek.com/freetype-zero-day-found-by-meta-exploited-in-paragon-spyware-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
