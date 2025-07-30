> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523322&idx=2&sn=347204929358f8a4c82b2634e62774cd

#  Veeam RCE漏洞导致域用户入侵备份服务器  
Sergiu Gatlan  代码卫士   2025-06-18 09:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Veeam 发布安全更新，修复了Veeam Backup & Replication (VBR) 中的多个漏洞，其中一个是RCE漏洞CVE-2025-23121。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTghPYBFyvxYKFqTiaX0lrmPzj6jAy4iafh48krG35dg7FMNeJ9XlaZeaicGDtB4AjAABu0nGAfo0HkA/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞由watchTowr 和 CodeWhite 公司的安全研究员报送，仅影响加入域的VBR版本。  
  
本周二，Veeam 公司发布安全公告提到，该漏洞可被已认证的域用户用于复杂度较低的攻击中，在 Backup Server上远程执行代码。该漏洞影响 VBR 12或后续版本，已在今天早些时候发布的版本12.3.2.3617中修复。  
  
虽然 CVE-2025-23121仅影响加入域的VBR版本，但任何域用户均可利用该漏洞，使其在这些配置中易遭滥用。遗憾的是，很多公司已将其备份服务器加入 Windows 域中，忽视 Veeam 公司提出的最佳实践即管理员应当使用单独的 Active Directory Forest 并通过双因素认证机制保护管理员账号的安全。  
  
今年3月份，Veeam公司修复了位于VBR 软件中的另外一个RCE漏洞，也影响加入域的版本。勒索团伙在多年前曾表示，一直都针对 VBR 服务器发动攻击，因为他们只要在受害者网络上部署勒索软件payload之前删除备份，就能窃取受害者的数据并拦截恢复工作。Sophos X-Ops 事件响应人员在去年11月披露称，9月份披露的另外一个 VBR RCE漏洞 (CVE-2024-40711) 正被用于部署勒索软件Frag。  
  
该漏洞还在去年10月份被Akira和Fog勒索攻击用于在易受攻击的 Veeam 备份服务器上执行远程代码。此前，Cuba 勒索团伙和受经济利益驱动的威胁组织 FIN7 与 Conti、Revil、Maze、Egregor 和 BlackBasta 勒索团伙协同利用 VBR 漏洞。  
  
Veeam 公司的产品用于全球超过55万名客户，其中82%排名财富500强，而74%全球排名2000名。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Veeam 修复Backup & Replication 中的严重RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522555&idx=1&sn=46e012bb1770fd23ba35da839b60f669&scene=21#wechat_redirect)  
  
  
[Veeam 提醒注意VSPC中的严重RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521684&idx=1&sn=b5ba5835dc8937327b3ded698979f0f2&scene=21#wechat_redirect)  
  
  
[Veeam：Backup Enterprise Manager 中存在严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519550&idx=2&sn=6b4de50a6ef98b37be097aae6daafa64&scene=21#wechat_redirect)  
  
  
[Veeam 修复备份管理平台中的RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519438&idx=1&sn=4e26daf80a580f4ffca69990e4991525&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-veeam-rce-flaw-lets-domain-users-hack-backup-servers/  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
