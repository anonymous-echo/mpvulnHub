#  Palo Alto Networks 修复退市 Migration Tool中的高危漏洞   
Ionut Arghire  代码卫士   2025-01-10 09:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周三，Palo Alto Networks 公司修复了 Expedition 迁移工具中的多个漏洞，其中一个是高危级别，可导致敏感信息遭暴露。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSOMNUxho4qo3QEk1VXicibNC1iasYdQ3ib1BBYFQ8eP5OfibhKXNwUf2p0C2uE0OIEI19mqMsJPAK5iavg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
这款免费工具此前被称为 “Migration Tool，Expedition”，可使组织机构从其它的防火墙厂商迁移到Palo Alto Networks NGFW 平台，它是一款临时的迁移解决方案，不应用于生产过程中，在2024年12月31日达到生命周期。  
  
该漏洞的编号是CVE-2025-0103（CVSS评分7.8），是一个高危的SQL注入漏洞，可导致认证攻击者读取数据库内容和任意文件。它还可被用于“在Expedition 系统上创建和删除任意文件。这些文件包括多种信息如用户名、明文密码、设备配置和运行 PAN-OS 软件的防火墙的设备API密钥。”  
  
该漏洞已在 Expedition 1.2.101中修复。该版本还修复了四个中低危漏洞，可导致 JavaScript 代码执行、任意文件删除、文件枚举和信息泄露后果。为缓解这些问题，客户应当“确保Expedition的所有网络访问权限仅向授权用户、主机和网络开放”，且如使用不频繁则应关闭该软件。  
  
Palo Alto Networks公司还提醒称之后将不再为 Expedition 发布更新，督促客户选择其它解决方案。该公司表示，“我们目前正在将该工具的核心功能迁移到新产品中。从2025年1月开始，Palo Alto Networks 公司将不再支持该 Expedition 工具，包括Expedition 1和Expedition 2 分支的所有版本。”本周三，该公司还表示已更新 Prisma Access Browser，其中还发布了六个 Chromium 漏洞的补丁。  
  
去年12月，谷歌推出 Chrome 131的两个更新以修复这些漏洞，其中两个高危的类型混淆漏洞位于 V8 JavaScript 引擎中，可被用于实现远程代码执行 (RCE) 后果，而发现这两个漏洞的研究员分别获得5.5万美元的奖励。  
  
Palo Alto Networks 公司并未提到这些漏洞是否遭在野利用。用户可从该公司的安全公告中找到更多信息。2024年11月，CISA提醒称，Expedition 中已在7月和10月修复的三个严重漏洞已遭利用。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Palo Alto 修复已遭利用的严重PAN-OS DoS 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521932&idx=1&sn=518332fa38f3263ee23df7a70c1187d3&scene=21#wechat_redirect)  
  
  
[Palo Alto 防火墙 0day 由低级开发错误引发](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521617&idx=2&sn=0e9ac32a3223e727cd6cd99460e0387e&scene=21#wechat_redirect)  
  
  
[Palo Alto Networks：注意潜在的 PAN-OS RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521440&idx=1&sn=3bf8ff26ce74c0c7fbfeb2701a773a5f&scene=21#wechat_redirect)  
  
  
[Palo Alto 修复多个严重的防火墙漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521075&idx=1&sn=2987012f618a751eabf08e620add0615&scene=21#wechat_redirect)  
  
  
[Palo Alto：注意！PAN-OS 防火墙 0day 漏洞已遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519289&idx=1&sn=86e226003b5da9dd0d6867f4b45fcb1a&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/palo-alto-networks-patches-high-severity-vulnerability-in-retired-migration-tool/  
  
  
题图：  
Pexels   
License  
  
****  
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
  
