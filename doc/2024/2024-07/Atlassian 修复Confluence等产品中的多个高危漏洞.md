#  Atlassian 修复Confluence等产品中的多个高危漏洞   
Ionut Arghire  代码卫士   2024-07-18 21:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周二，软件厂商 Atlassian 发布安全更新，修复了位于 Bamboo、Confluence 和 Jira 产品中的多个高危漏洞。**  
  
  
  
Atlassian 公司紧急呼吁用户注意 Bamboo Data Center 和 Server 更新修复的两个高危漏洞，其中一个影响 UriComponentsBuilder 依赖，可导致未认证攻击者执行服务器端请求伪造 (CSRF) 攻击。该漏洞编号为CVE-2024-22262，影响Data Center 和 Bamboo Server 版本 9.0.0、9.1.0、9.2.1、9.3.0、9.4.0、9.5.0和9.6.0，已在版本9.6.3 LTS 和9.2.14 LTS 中修复。  
  
第二个漏洞是CVE-2024-21687，是文件包含漏洞，可导致攻击者“使该应用展示本地文件内容，或执行已本地存储在服务器中的其它文件。”该漏洞影响 Bamboo Data Center and Server 9.0.0、9.1.0、9.2.0、9.3.0、9.4.0、9.5.0 和 9.6.0版本。攻击者需要认证才能实施成功利用，已在版本9.6.4 LTS 和 9.2.16 LTS 中修复。  
  
该漏洞还修复了 Confluence Data Center 和 Confluence Server 中的7个高危漏洞，其中5个是位于 Apache Commons Compress 依赖中的拒绝服务漏洞。Atlassian 公司表示，“该库易受攻击的版本存在于 Confluence 中，但并未遭利用。因此，我们的产品并非本身易受攻击以及面临风险。升级会迁移到该库的更新版本，但任何未来的升级皆如此。”这些漏洞已在 Confluence Data Center 版本8.9.4、8.5.12 LTS 和 7.19.25 LTS以及 Confluence Server 8.5.12 LTS 和 7.19.25 LTS 中修复。  
  
Atlassian 公司还修复了与绑定的JDK相关但不影响 .zip/.tar.gz 发行版本的12个CVE漏洞。第三方依赖弱点在Confluence Data Center 和 Server 7.0.1版本中修复。  
  
另外，Atlassian 公司还修复了一个存储型跨站脚本 (XSS) 漏洞，可导致认证攻击者在受害者浏览器中执行任意 HTML 或 JavaScript 代码。  
  
Jira Software Data Center 和服务器以及 Jira Service Management Data Center 和 Server 修复了位于 XStream 依赖中的一个高危漏洞 (CVE-2022-41996)，它可被用于引发拒绝服务条件。该漏洞的补丁已包含在 Jira Software Data Center 和 Server 版本9.8.0、9.12.0 LTS 和9.4.18 LTS，以及Jira Service Management Data Center 和 Server 版本5.8.0、5.12.0 LTS 和 5.4.18 LTS 中。  
  
Atlassian 公司并未提及这些漏洞是否已遭在野利用，但建议用户尽快应用这些补丁。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian Confluence 高危漏洞可导致代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519665&idx=2&sn=86259d3f96b173403f1a65b601fc1989&chksm=ea94bcdbdde335cd0f308951f098245eea81c0364b1a3726dc92bad88f1ce58de6b53eef24ec&scene=21#wechat_redirect)  
  
  
[Atlassian 发布20多个漏洞，含严重的 Bamboo 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519117&idx=2&sn=c0c8035f5617c6f76c73e71b9e73f04f&chksm=ea94bae7dde333f1efbbaeff72b89df023bbc2e6d408df713a753e060c09ff210656828d17d9&scene=21#wechat_redirect)  
  
  
[Atlassian Confluence 远程代码执行漏洞(CVE-2023-22527)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518678&idx=1&sn=aedf682361f621f14474e78244d3242e&chksm=ea94b8bcdde331aa278b8d6c8fe7f1df9ec253aa21e960355a967894be85796756b54e173c95&scene=21#wechat_redirect)  
  
  
[Atlassian 修复多款产品中的多个严重RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518302&idx=1&sn=9ede9c29a5c7c063571222672e754926&chksm=ea94b934dde330222c90b770d277247b3ad535c2b85b8082228c17630922ff9ea123ab19691f&scene=21#wechat_redirect)  
  
  
[Atlassian 提醒注意严重的 Confluence 漏洞，可导致数据丢失](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518036&idx=1&sn=ad96c9dc39840b68b765672413fcb367&chksm=ea94b63edde33f289d197760bd0839cbaaa57edd6a2e5e6d5e9749ce290abfea667c37d2ba69&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/atlassian-patches-high-severity-vulnerabilities-in-bamboo-confluence-jira/  
  
  
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
  
