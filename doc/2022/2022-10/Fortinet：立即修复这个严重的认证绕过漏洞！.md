#  Fortinet：立即修复这个严重的认证绕过漏洞！   
Sergiu Gatlan  代码卫士   2022-10-08 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
Fortinet公司提醒管理员称，立即将FortiGate 防火墙和 FortiProxy 网络代理更新至最新版本，修复之前版本中的严重漏洞（CVE-2022-40684）。  
  
  
该漏洞是位于管理员界面上的一个认证绕过漏洞，可导致远程威胁者登录到未修复设备中。  
  
Fortinet 公司在客户支持安全通告中指出，“通过FortiOS和FortiProxy 中的可选路径或信道而实施的认证绕过，可导致未认证攻击者通过特殊构造的 HTTP或HTTPS请求在管理员接口上执行操作。”  
  
该公司指出，“这是一个严重漏洞，应当立即处理。”该公司还向客户发送邮件，建议客户立即更新至最新版本。它提醒称，“由于攻击者可远程利用该漏洞，Fortinet强烈建议使用易受攻击版本的所有客户立即升级版本。”  
  
从Shodan搜索结果来看，超过10万台FortiGate防火墙可从互联网访问，尽管目前尚不清楚其管理接口是否已遭暴露。  
  
易受影响的产品包括：  
  
- FortiOS：7.0.0到7.0.6版本以及7.2.0到7.2.1版本  
  
- FortiProxy：7.0.0到7.0.6版本以及7.2.0版本  
  
  
  
从客户支持安全通告来看，Fortinet 公司在本周四发布安全补丁，要求客户将易受攻击设备升级至FortiOS/FortiProxy 版本7.0.7或7.2.2版本。  
  
  
**缓解措施**  
  
  
  
Fortinet 公司还为无法立即部署安全更新的组织机构发布缓解措施。  
  
要阻止远程攻击这绕过认证并登录易受攻击的 FortiGate 和 FortiProxy 部署，客户应当通过local-in-policy来限制可访问管理员接口的IP地址。然而，在和“精选客户”的提前沟通中，Fortinet公司建议管理员禁用远程管理用户接口，确保拦截潜在攻击。该公司表示，“如果设备无法即使升级，则应当立即禁用面向互联网的 HTTPS管理员，直到执行升级时。”  
  
Fortinet 公司的发言人拒绝就该漏洞是否遭在野利用置评，并表示公司将在后续发布更多消息。这名发言人指出，“客户沟通通常会详细说明最及时的指南和推荐步骤，以最好地保护组织机构的安全。机密的提前客户沟通情况中包括关于安全公告的尽早提醒，使客户能够进一步增强安全态势，而这些安全通告将在几天内向更广范围的客户发布。”  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet 修复多个路径遍历漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512788&idx=3&sn=894340534673ba25a49c72eec950b0d7&chksm=ea9483bedde30aa8e9c0b3355eeee1ce56ec6cb1f2d55b60888cea9487bd8397fff4294a955d&scene=21#wechat_redirect)  
  
  
[黑客利用老旧安全缺陷攻破数万未打补丁的 Fortinet VPN 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507850&idx=3&sn=2ef6c8e24754e7f6c84db9a5eebc9841&chksm=ea94eee0dde367f6cc369d9e7480161d5b32ed4fd175215145390fd16c0d196639a57d4f0bbe&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重漏洞，可导致未认证黑客以最高权限执行任意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506504&idx=2&sn=35c13960da760d7876e70f5121125275&chksm=ea94eb22dde36234754f1f38fe2d445936f50fb540211ea13e2516f5344a7132ca0857e97f94&scene=21#wechat_redirect)  
  
  
[Fortinet 防火墙受高危漏洞影响，可遭远程攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506050&idx=3&sn=5190aa1ab97106f1933f5b6bed5612c6&chksm=ea94e9e8dde360fe6594ce06673ef43141a38022b2bb95ce168634ffbac685503db7be04db69&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/fortinet-warns-admins-to-patch-critical-auth-bypass-bug-immediately/  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
