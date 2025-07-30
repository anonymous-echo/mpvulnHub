#  至今未修复的NASA 网站漏洞   
 关键基础设施安全应急响应中心   2023-06-08 15:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogsj8QrZq6o0ZOKsgibY2hicBBdzJQReV0obw4XiaS9xAeMG0DkuzicPceyk48OibUNkj7ibiaichhK16P0y9A/640?wx_fmt=png "")  
  
据悉，Cybernews 研究团队独立发现了一个困扰 NASA 天体生物学网站的开放式重定向漏洞。漏洞发现后，研究团队发现一个开放的漏洞赏金计划研究人员已经早在 2023年1月14日就已经发现了它，但该机构没有解决和修复它。  
  
这意味着世界领先的太空研究设施之一，使全球用户至少在 2023年5月之前的几个月内面临风险。攻击者可能会利用该漏洞将任何人重定向到恶意网站，促使用户放弃他们的登录凭据，信用卡号或其他敏感数据。  
  
自4月初以来，Cybernews 研究团队已多次联系 NASA，但在发表本文之前尚未收到任何回复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogsj8QrZq6o0ZOKsgibY2hicBB4tfd1q7RI0y68iafg3AJKR1uXDick841fuMkQKEVVsdia912RCAfGblLg/640?wx_fmt=png "")  
  
**什么是开放重定向漏洞？**  
  
开放重定向缺陷类似于作弊的出租车司机，好比你叫了一辆出租车，并告诉司机你想去哪里。他们没有验证目的地，而是带你去一个令人讨厌的地区。类似尝试访问 astrobiology.nasa.gov 的用户很容易就进入了恶意网站。通常，Web 应用程序会验证或清理用户提供的输入，例如 URL 或参数，以防止发生恶意重定向。  
  
Cybernews 研究人员解释说：“攻击者可以利用该漏洞，通过将恶意 URL 伪装成合法 URL 来诱骗用户访问恶意网站或钓鱼页面。”  
  
**为什么开放重定向漏洞很危险？**  
  
攻击者可以使用附加参数修改 NASA 的网站，并将用户引导至他们选择的位置。恶意重定向甚至可能类似于 NASA 的页面，只是用要求输入信用卡数据的提示进行修饰。  
  
此外，威胁行为者可以利用开放的重定向错误将用户引导至网站，这些网站在登陆后立即将恶意软件下载到他们的计算机或移动设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGogsj8QrZq6o0ZOKsgibY2hicBBAVZcWH7F6nM08vTZSxSiaDAevyXXnRfCRwVMx0dkWubwpbRGKPrLeCA/640?wx_fmt=png "")  
  
另一种利用该漏洞的方法是通过将用户重定向到展示低质量内容或垃圾邮件的网站来操纵搜索引擎排名。  
  
虽然我们无法确认是否有人真正利用了困扰 NASA 网站的漏洞，但Cybernews团队以及开放漏洞赏金计划的研究人员均发现了该漏洞。  
  
由于开放重定向缺陷已经存在了几个月，可能还有其他人无意中发现了同样的发现  
  
**如何缓解开放重定向漏洞？**  
  
开放重定向缺陷至关重要，因为它们允许恶意行为者执行网络钓鱼攻击、窃取凭据和传播恶意软件。  
  
为避免此类事故，Cybernews团队强烈建议网站所有者验证所有用户输入，包括 URL，以确保输入仅包含有效值。  
  
“这可能包括使用正则表达式来验证 URL 的格式是否正确，检查 URL 是否来自受信任的域，以及验证 URL 不包含任何意外或恶意字符”研究人员解释说。  
  
  
  
原文来源：E安全  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
