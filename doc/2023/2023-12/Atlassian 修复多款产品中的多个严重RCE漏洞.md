#  Atlassian 修复多款产品中的多个严重RCE漏洞   
Bill Toulas  代码卫士   2023-12-07 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Atlassian 公司发布安全公告，修复四个严重的远程代码执行 (RCE)漏洞，它们影响 Confluence、Jira 和 Bitbucket 服务器及 macOS 版本的Companion app。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSPcwrmiaKicicBnDibg7lsv2uqtoR3NTicYpsP52Ptk0CzUfLO24ek0pD3mP3t1zuYMAJ0fbMOP7B4Thw/640?wx_fmt=gif&from=appmsg "")  
  
  
所有漏洞均为严重级别漏洞，根据 Atlassian 公司的内部评估CVSS评分至少都是9分。不过，Atlassian 公司建议企业根据自身的IT环境评估修复方案的适用性。  
  
Atlassian 公司指出，这些公司均未遭在野利用。然而，鉴于 Atlassian 公司产品的热门程度以及在企业环境中大量部署，系统管理员应当优先应用可用的更新。该公司本月修复的四个 RCE 漏洞如下：  
  
- CVE-2023-22522：模板注入漏洞可导致认证用户，包括具有匿名访问权限的用户，将不安全的输入注入 Confluence 页面（严重级别，严重性评分9分）。该漏洞影响所有4.0.0之后至8.5.3的 Confluence Data Center 和 Server 版本。  
  
- CVE-2023-22523：Assets Discovery 代理中存在提权 RCE 漏洞，影响 Jira Service Management Cloud、Server 和 Data Center（严重级别，严重性为9.8）。易受攻击的 Asset Discovery 版本是Cloud 3.2.0以下和 Data Center and Server 6.2.0版本。  
  
- CVE-2023-22524：绕过拦截列表和 Confluence Server and Data Center 的macOS 版 Companion app 上的 macOS Gatekeeper，影响所有早于2.0.0版本之前的 app（严重级别，严重性评分9.6）。  
  
- CVE-2022-1471：位于 SnakeYAML 库中的RCE漏洞，影响 Jira、Bitbucket 和 Confluence 产品的多个版本（严重级别，严重性评分9.8）。  
  
  
  
要修复以上所有四个漏洞，建议用户更新至如下任一产品版本：  
  
- Confluence Data Center and Server 7.19.17 (LTS)、8.4.5和8.5.4 (LTS)。  
  
- Jira Service Management Cloud (Assets Discovery) 3.2.0 或后续版本以及Jira Service Management Data Center and Server (Assets Discovery) 6.2.0 或后续版本。  
  
- Atlassian Companion App for MacOS 2.0.0 或后续版本。  
  
- Automation for Jira (A4J) Marketplace App 9.0.2 和 8.2.4。  
  
- Bitbucket Data Center and Server 7.21.16 (LTS)、8.8.7、8.9.4 (LTS)、 8.10.4、8.11.3、8.12.1、8.13.0、8.14.0、8.15.0 (Data Center Only)和 8.16.0 (Data Center Only)。  
  
- Confluence Cloud Migration App (CCMA) 3.4.0。  
  
- Jira Core Data Center and Server、Jira Software Data Center and Server 9.11.2、9.12.0 (LTS) 和9.4.14 (LTS)。  
  
- Jira Service Management Data Center and Server 5.11.2, 5.12.0 (LTS) 和5.4.14 (LTS)。  
  
  
  
如目前无法卸载 Asset Discovery 代理应用 CVE-2023-22523的补丁或必须延迟，则Atlassian 公司提供了一项临时的缓解措施，可拦截用于与代理通信的端口，该端口默认为51337。  
  
对于CVE-2023-22522而言，不存在缓解措施。如管理员无法立即应用补丁，则 Atlassian 公司建议管理员备份受影响的实例并将其下线。如管理员无法应用CVE-2023-22524的补丁，则公司建议卸载 Atlassian Companion App。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian 提醒注意严重的 Confluence 漏洞，可导致数据丢失](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518036&idx=1&sn=ad96c9dc39840b68b765672413fcb367&chksm=ea94b63edde33f289d197760bd0839cbaaa57edd6a2e5e6d5e9749ce290abfea667c37d2ba69&scene=21#wechat_redirect)  
  
  
[Atlassian 紧急修复已遭利用的 Confluence 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517813&idx=2&sn=6a3b7d66586da1ad6c1cb57b1db81155&chksm=ea94b71fdde33e09a176e23f52637a496b5d244d21adece15ff30273b5a330a21fea95f10aff&scene=21#wechat_redirect)  
  
  
[Atlassian 安全更新修复多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517726&idx=2&sn=fb70a13cea95f2a283f72cea5e804abc&chksm=ea94b774dde33e62ceae3c08c4f637d76f5c3e2592a17823a66b9442cfc21a4a65b04d7edfce&scene=21#wechat_redirect)  
  
  
[第三方app受陷，Atlassian 数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515624&idx=3&sn=67fc0501190042defabcc173a6eb618f&chksm=ea948c82dde30594c6d827c3f9a2ec0f74bc3ac9f01de20c08188c4f469b2a74cbf9381d0a01&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Crowd 和 Bitbucket 产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514682&idx=2&sn=dc35e642f56cb043c698c74c4a7cc1db&chksm=ea948b50dde3024635cc241de37f67ec45fccba1bb52808e5a89a1908c6cd04233a2502e782c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/atlassian-patches-critical-rce-flaws-across-multiple-products/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
