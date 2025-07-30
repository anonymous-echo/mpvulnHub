#  Adobe紧急修复严重的ColdFusion 路径遍历漏洞   
Sergiu Gatlan  代码卫士   2024-12-24 09:45  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**Adobe 公司发布带外安全更新，修复了PoC 利用代码已公开的、严重的 ColdFusion 路径遍历漏洞CVE-2024-53961。**  
  
  
  
  
周一，Adobe 表示CVE-2024-53961由一个路径遍历弱点引发，影响 Adobe ColdFusion 版本2023和2021，可导致攻击者读取易受攻击服务器上的任意文件。Adobe 公司提到，“Adobe 发现CVE-2024-53961已存在已知的 PoC 利用代码，可导致任意文件系统读取。”该公司还提醒客户称，将该漏洞评级为“优先级1级”，因为“从既定产品版本和平台方面的在野利用情况来看，它遭针对性攻击的风险更高”。  
  
Adobe 公司建议管理员尽快安装今天发布的紧急安全补丁（ColdFusion 2021 Update 18和ColdFusion 2023 Update 12），“例如，在72小时内”，并应用在 ColdFusion 2023和ColdFusion 2021 锁定指南中所列出的安全配置设置。  
  
虽然Adobe 公司尚未披露该漏洞是否已遭在野利用，它建议客户在今天查看其更新的序列过滤器文档，获得关于拦截不安全 Wddx 反序列化攻击的更多信息。  
  
CISA曾在5月份督促软件公司在交付产品前消除路径遍历漏洞，因为攻击者可利用这类漏洞访问敏感数据，包括可用于暴力攻击业已存在的账户并攻陷目标系统的凭据。CISA提到，“目录遍历等漏洞最少从2007年开始就被称作‘不可原谅的’漏洞。尽管如此，目录遍历漏洞（如CWE-22和CWE-23）仍然是普遍存在的漏洞类型。”  
  
2023年7月，CISA还要求联邦机构在8月10日前保护 Adobe ColdFusion 服务器免受两个已遭利用的严重漏洞（CVE-2023-29298和CVE-2023-38205）的影响，而其中一个漏洞当时是0day状态。  
  
一年前  
CISA还曾披露称，黑客正在利用另外一个严重的 ColdFusion 漏洞CVE-2023-26360自2023年6月起攻陷过时的政府服务器。该漏洞自2023年3月起就已被活跃用于“非常有限的攻击活动”中。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Adobe 修复Acrobat Reader 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520782&idx=1&sn=e5eaa66675d142213f7058469e5446bb&scene=21#wechat_redirect)  
  
  
[Adobe Acrobat Reader 高危漏洞加入CISA必修清单](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517855&idx=2&sn=5ea5455de3ad27bd027a363a4b11a95a&scene=21#wechat_redirect)  
  
  
[补丁星期二：微软、Adobe和Firefox纷纷修复已遭利用的 0day 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517643&idx=1&sn=83e85b6b9bf3a9f0cf0c1843c9589950&scene=21#wechat_redirect)  
  
  
[CISA 将Adobe ColdFusion中的这个严重漏洞列入必修清单](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517437&idx=1&sn=561e8ad37f584120784a95e9ad1c33f4&scene=21#wechat_redirect)  
  
  
[CISA紧急提醒：Adobe ColdFusion漏洞已遭在野利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515947&idx=3&sn=76c36938bf1b7401950fc62730020638&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/adobe-warns-of-critical-coldfusion-bug-with-poc-exploit-code/  
  
  
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
  
