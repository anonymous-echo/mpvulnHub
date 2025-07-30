#  ZDI称微软 Exchange 出现4个新0day，可导致RCE和数据被盗   
Bill Toulas  代码卫士   2023-11-06 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**微软 Exchange 中存在4个0day漏洞，可被攻击者远程利用执行任意代码或在受影响设备上泄露敏感信息。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQBIyb7l7XvzXypz894pIzFsSkss49z8GS076FRHsZfp64Gzl3ntVVKdquBDTnia6tQPKbBo6Gepmg/640?wx_fmt=png "")  
  
  
这些0day 漏洞是由趋势科技的ZDI 团队披露的，后者在2023年9月7日和8日告知微软。尽管微软确认了这些漏洞，但其开发工程师认为严重程度不足以得到立即修复，因此推迟修复动作。  
  
ZDI 不认同该看法，并决定通过自身的追踪ID编号来发布这些漏洞，提醒 Exchange 管理员注意这些漏洞带来的风险。  
  
这些漏洞概述如下：  
  
- ZDI-23-1578：“ChainedSerializationBinder” 类中存在一个远程代码执行 (RCE) 漏洞。该类中的用户数据未得到正确验证，导致攻击者可反序列化不受信任的数据。成功利用该漏洞可导致攻击者以系统权限执行任意代码。  
  
- ZDI-23-1579：该漏洞位于 “DownloadDataFromUri” 方法中，是因为在资源访问前的URI验证不充分造成的。攻击者可利用该漏洞访问 Exchange 服务器中的敏感信息。  
  
- ZDI-23-1580：该漏洞位于 “DownloadDataFromOfficeMarketPlace”方法中，也是因为URI验证不当造成的，可导致未授权的信息泄露后果。  
  
- ZDI-23-1581：位于 CreateAttachmentFromUri 方法中，与上述URI验证不当的漏洞类似，也可导致敏感信息遭暴露。  
  
  
  
要利用这些漏洞均需要获得认证，因此它们的CVSS评分介于7.1至7.5之间。另外，要求认证是一个缓解因素，而这可能是微软并未优先修复的原因所在。  
  
尽管如此，应该注意的是，网络犯罪分子获得 Exchange 凭据的方法有很多，包括暴力破解弱密码、执行钓鱼攻击、购买凭据或者从信息窃取器日志中获取。话虽如此，但不应轻视上述漏洞的重要性，尤其是 ZDI-23-1578 (ZDI) 漏洞可导致系统遭完全攻陷。  
  
ZDI 建议称唯一重要的缓解措施是限制与 Exchange 应用的交互。然而，对于很多使用该产品的公司和组织机构而言无法被接受。建议即使账户凭据被攻陷时，也要执行多因素认证，阻止网络犯罪分子访问 Exchange 实例。  
  
微软的一名发言人回应称，“感谢这名漏洞发现人员在协同漏洞披露的条件下提交了这些漏洞，我们致力于采取必要措施保护客户安全。我们已经审计了这些报告并发现漏洞要么已被修复，要么未满足严重性分类指南中要求的立即服务标准。我们将在未来的产品版本中评估修复事宜并妥善更新。”  
  
另外，微软还对每个漏洞提供了更多信息：  
  
- ZDI-23-1578相关：应用了八月安全更新的客户已受到保护。  
  
- ZDI-23-1581：所述技术要求攻击者提前拥有访问邮件凭据的权限，且未有证据表明该漏洞可用于获得提权权限。  
  
- ZDI-23-1579：所述技术要求攻击者提前拥有访问邮件凭据的权限。  
  
- ZDI-23-1580：所述技术要求攻击者提前拥有访问邮件凭据的权限，且未有证据表明该漏洞可用于访问敏感的客户信息。  
  
  
  
****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软督促客户修复本地 Exchange 服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515408&idx=1&sn=719e32aee7a384a488836ef79cc13dd3&chksm=ea948c7adde3056cabb6547dcc9db6b78521848dae15c19d2baf51edd05c565ed90d4dbd4f8f&scene=21#wechat_redirect)  
  
  
[【已复现】Microsoft Exchange Server "OWASSRF" 漏洞安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515107&idx=1&sn=47eca1a57ee9fd7e5cb0b36080483ab3&chksm=ea948a89dde3039f969c6fe7e6e1558310d44cc7a2c51cd0e7f4b2aed00e0d79952a523ded02&scene=21#wechat_redirect)  
  
  
[微软证实称两个Exchange 0day 正遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514120&idx=1&sn=875f2a8038dd18f4393f68e4958721d8&chksm=ea948962dde3007476979db37549927911d0a40f66cd92734aac2576932e65c02e814b4d2292&scene=21#wechat_redirect)  
  
  
[黑客在被黑的MS Exchange Server 上部署 IceApple 利用框架](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511792&idx=2&sn=9fc836e07a156357940dd2eb58198419&chksm=ea949f9adde3168ce5621cca35726a5e8edd36548400b016da2bcbd67093b7aba1cab58d6cc6&scene=21#wechat_redirect)  
  
  
[微软将本地版Exchange、SharePoint和Skype 纳入漏洞奖励计划](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511275&idx=4&sn=efe2927c135f8cf5c5c2663330e1a4f3&chksm=ea949d81dde31497c5ade51ddb1de4709626af7f0d773fe10c928c1eb7a230fd5b290868d5ff&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/microsoft/new-microsoft-exchange-zero-days-allow-rce-data-theft-attacks/  
  
  
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
  
