#  GitHub 上的虚假0day PoC 推送 Windows 和 Linux 恶意软件   
Bill Toulas  代码卫士   2023-06-15 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRMqB8dM1tiajzZglFy2PMGvn76vqY5ZO8HppnftCO1bN4cy4CY1zmSg0amjBAZAHewubO3mlYluZg/640?wx_fmt=gif "")  
  
**黑客正在推特和 GitHub 上假冒研究员发布虚假的 0day 漏洞利用，在Window 和 Linux 设备上分发恶意软件。**  
  
  
这些恶意利用由虚假网络安全公司 “High Sierra Cyber Security” 的虚假研究员发布，他们在推特上推销 GitHub 仓库，可能瞄准的是涉及漏洞研究的企业。这些仓库看似合法，而其维护人员冒充 Rapid7 公司和其它安全企业的研究员，甚至还使用真正研究员的头像。  
  
这些人员在推特上维护账户，为其在 GitHub 上的研究和代码仓库增加合法性并从社交媒体平台上搜罗受害者。  
  
这起活动由 VulnCheck 发现，他表示该攻击最早开始于2023年5月，冒充者推销热门软件如 Chrome、Discord、Signal、WhatsApp 和 Microsoft Exchange 等中0day 漏洞的利用。  
  
在所有情况下，这些恶意仓库中都托管着 Python 脚本 (‘poc.py’)，作为Linux 和 Windows 系统的恶意软件加载器。该脚本根据受害者所用系统从外部 URL 下载 ZIP 文档，Linux 用户会下载 “cvslinux.zip” 而 Windows 用户会收到 “cvswindows.zip”。该恶意软件被保存到 Windows %Temp% 或 Linux /home/<username>/.local/share 文件夹，被提取并执行。  
  
VulnCheck 报告称，该 ZIP 文档 (‘cvs_windows.exe’) 中所包含的 Windows 二进制被 VirusTotal 上60%的 AV 引擎标记，而Linux 二进制 (“cves_linux’) 更加隐秘，仅被三个扫描器捕捉。  
  
目前尚不清楚所安装的恶意软件性质，不过这两个可执行文件均安装 TOR 客户端，而 Windows 版本被某些引擎识别为密码窃取木马。虽然这起攻击活动是否成功仍不清楚，但 VulnCheck 提到威胁行动者似乎是持久性质，每当被举报和删除后，就会新建账户和仓库。  
  
目前，应避免如下7个GitHub 仓库：  
  
- github.com/AKuzmanHSCS/Microsoft-Exchange-RCE  
  
- github.com/MHadzicHSCS/Chrome-0-day  
  
- github.com/GSandersonHSCS/discord-0-day-fix  
  
- github.com/BAdithyaHSCS/Exchange-0-Day  
  
- github.com/RShahHSCS/Discord-0-Day-Exploit  
  
- github.com/DLandonHSCS/Discord-RCE  
  
- github.com/SsankkarHSCS/Chromium-0-Day  
  
  
  
另外，如下推特账户是冒牌研究员，是不可信的：  
  
- twitter.com/AKuzmanHSCS  
  
- twitter.com/DLandonHSCS  
  
- twitter.com/GSandersonHSCS  
  
- twitter.com/MHadzicHSCS  
  
  
  
安全研究员和网络安全爱好者从未知仓库下载脚本时应警惕。  
  
朝鲜 Lazarus 国家黑客组织在2021年1月实施了类似攻击活动。该组织在社交媒体创建虚假漏洞研究员人设，通过恶意软件和 0day 攻击研究员。同年晚些时候，他们通过木马版 IDA Pro 逆向软件安装远程访问木马。最近，研究员发现 GitHub 平台上的数千个仓库提交了多个漏洞的虚假 PoC 利用，其中一些以恶意软件、恶意 PowerShell、遭混淆的信息窃取下载工具、Cobalt Strike 释放器等感染用户。  
  
威胁行动者通过攻击漏洞研究和网络安全社区访问可用于攻击中的漏洞研究成果。更糟糕的是，在很多情况下，该恶意软件会提供对网络安全公司网络的初始访问权限，从而进一步导致数据盗取和勒索攻击活动。  
  
随着网络安全企业倾向于在客户端上放置敏感信息如漏洞评估、远程访问凭据甚至是未披露的 0day 漏洞，这种访问权限对于威胁行动者而言价值很大。因此，从 GitHub 下载代码时，审计所有代码中是否存在恶意行为十分重要。在本案例中，恶意软件的下载和执行在 PoC 中显而易见，但由于威胁行动者可能混淆恶意代码，因此并非所有情况皆如此。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[推特源代码在GitHub 泄漏三个月之久](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516064&idx=3&sn=1ee10d19e2269fa8cd24675a1e68c64e&chksm=ea948ecadde307dc4777959fc9483de5297fb419a29d3f05ab2d53e1d69e2929d4569cae5d0b&scene=21#wechat_redirect)  
  
  
[朝鲜黑客伪装成三星招聘人员诱骗安全研究员，或发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509458&idx=2&sn=f528549b7c0e1e22f6a3c2cd5b90907e&chksm=ea9494b8dde31dae2735d4955bac8d240dbe82c8d42406c861e321aa05b90244f9bde35e0dc4&scene=21#wechat_redirect)  
  
  
[谷歌：朝鲜国家黑客第二次攻击安全研究员](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503187&idx=3&sn=130346ddc56e19bbc5c3a455ccd76d17&chksm=ea94fc39dde3752fc84b18ef3f4b7e353fc48d5028c9cef04b7ded692bed52b66887ea454ea8&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/fake-zero-day-poc-exploits-on-github-push-windows-linux-malware/  
  
  
题图：Pexels License  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
