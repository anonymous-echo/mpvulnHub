#  Firefox和Tor浏览器遭遇神秘0Day漏洞攻击   
 网络安全与人工智能研究中心   2024-11-28 08:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibw4dySDkrQpo0dd5dnR2u37gPCTjvia4VEdTaymicjbuMnVtb2CjAONY915picE4e1u4aN6icDNaSIk9Q/640?wx_fmt=gif "")  
  
  
俄罗斯某APT组织将攻击与Windows10和11中一个以前未知的漏洞链接起来，在受害者的计算机上安装后门。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibz9HE9nsRk3sZEGLOlFZicXQPhUN4Xr0jKHcWNvcQf2zvKbnxMwuYSDGCagMsDWm0C7bzQzsiba3Rzg/640?wx_fmt=png&from=appmsg "")  
  
  
近日，俄罗斯某APT组织被发现利用两个以前未知的漏洞攻击Windows PC上的Firefox和Tor浏览器用户。安全厂商ESET指出，这些零日漏洞攻击可能造成“广泛传播”，主要针对欧洲和北美的用户。  
  
  
俄罗斯黑客通过一个伪装成假新闻组织的恶意网页进行传播。如果易受攻击的浏览器（Firefox和Tor浏览器 ）访问该页面，它可以秘密触发软件漏洞在受害者的PC上安装后门。  
**最关键的是，ESET警告称，这个过程无需与网页进行互动。**  
  
****  
目前，尚不清楚是如何传播包含恶意软件的网页链接。但第一个漏洞（编号：CVE-2024-9680），可以导致Firefox和Tor浏览器运行恶意计算机代码。  
  
  
黑客还将攻击与Windows 10和11中的第二个漏洞（编号：CVE-2024-49039）链接起来，在浏览器和操作系统上执行更多的恶意计算机代码，最终实现秘密下载并安装一个后门。  
**该后门能够监视PC，包括收集文件、截取屏幕截图以及窃取浏览器cookie和保存的密码。**  
  
  
目前，Mozilla、Tor和微软已经修补了这些漏洞。这两个浏览器于10月9日修复了该漏洞，微软在11月12日修补了另一个漏洞，并建议用户及时更新。  
  
如果用户未能修补漏洞，黑客可以继续利用漏洞发起此类攻击。  
ESET的杀毒产品数据显示，自10月份（可能更早）以来，某些国家已有超过250家企业用户可能遇到了这些攻击。  
  
  
虽然还没有掌握确凿的证据，但ESET认为该攻击的幕后是名为“RomCom”俄罗斯APT组织，后者专注于网络犯罪和间谍活动。这也是RomCom继2023年6月滥用微软CVE-2023-36884 漏洞后，第二次被发现利用关键零日漏洞，策划具有威胁性的攻击活动。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibw4dySDkrQpo0dd5dnR2u37LOW9y4urp43vAdtNYM42sbWic0ZPL8M5x6Y9J6nU38zHlxeXCbpm8eQ/640?wx_fmt=png "")  
  
来源｜“FreeBuf”公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  
