#  Active! mail 中的RCE 0day漏洞用于攻击位于日本的机构   
Bill Toulas  代码卫士   2025-04-23 10:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Active! mail 中存在一个远程代码执行 (RCE) 0day 漏洞，现已被用于攻击位于日本的大型组织机构。**  
  
  
Active! mail 最初是由 TransWARE 开发的一款基于 web 的邮件客户端，之后被Qualitia 公司收购。这两家公司均为日企。  
  
Active! mail 在全球的使用规模虽然不如 Gmail 或 Outlook，但常被日本大型企业、大学、政府机构和银行用作日语环境下的群件组件。该公司用于超过2250家组织机构，账号超过1100万个，在日本商务网络邮件市场中占据重要地位。  
  
上周晚些时候，Qualitia 公司发布基于栈的缓冲溢出漏洞CVE-2025-42599（CVSS v3 9.5）的安全通告提到，该漏洞影响所有受支持OS平台上 BuildInfo: 6.60.05008561 及以下的所有 Active! 版本。安全公告指出，“如果远程第三方发送恶意构造的请求，则可能会触发任意代码执行或拒绝服务条件。”  
  
尽管 Qualitia 公司提到正在调查该漏洞是否已遭利用，但日本CERT已确认漏洞遭活跃利用，督促所有用户尽快升级至最新版本 Active! mail 6 BuildInfo: 6.60.06008562。  
  
日本web托管和IT服务 (SMB) 提供商 Kagoya 在上周末报送多起外部攻击，并临时暂停服务。该公司发布安全公告提到，“我们认为该问题与QUALITIA（开发者）披露的一个漏洞有关。”随后web 托管和IT服务提供商 WADAX 也报送了疑似遭利用尝试后，服务被宕机的情况。WADAX 公司表示，“目前，我们尚无法保证客户能够安全使用服务。因此，为客户安全考虑，谨慎起见，我们临时暂停了 Active! mail 服务。”  
  
Macnica 公司的安全研究员 Yutaka Sejiyama 表示，至少有227台暴露在互联网上的 Active! 服务器可能遭此攻击，而其中63台用于大学院校。  
  
日本CERT 为那些无法立即应用安全更新的人员提出了多项具体的缓解措施，包括配置WAF启用HTTP请求主题检查，以及如果multipart/from-data 标头的大小超过某个门槛则进行拦截。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Roundcube Webmail XSS 漏洞被用于窃取登录凭据](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521165&idx=2&sn=7bfb29f17ff7d1e5ee3a692d0325509c&scene=21#wechat_redirect)  
  
  
[Mailcow Mail Server 在多个漏洞，可导致RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519800&idx=2&sn=9ec908fe16262acbc252fd098d15c022&scene=21#wechat_redirect)  
  
  
[Gmail 邮件AMP 特性中的XSS 漏洞价值5000美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513431&idx=4&sn=0f7e90b83018147e3eef2dc9b2eee50e&scene=21#wechat_redirect)  
  
  
[详情和 PoC 发布后，谷歌匆忙修复严重的 Gmail 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494754&idx=2&sn=20784d82d526896a4ff4f93754714957&scene=21#wechat_redirect)  
  
  
[邮件地址解析存在 Mailsploit 漏洞 已有33个客户端受影响](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485416&idx=3&sn=bf020820d8f15b9df0d40648c77de965&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/active-mail-rce-flaw-exploited-in-attacks-on-japanes  
e-orgs/  
  
  
  
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
  
