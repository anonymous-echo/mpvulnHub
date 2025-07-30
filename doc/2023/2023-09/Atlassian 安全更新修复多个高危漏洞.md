#  Atlassian 安全更新修复多个高危漏洞   
Ionut Arghire  代码卫士   2023-09-22 17:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**本周，Atlassian 公司修复了影响 Jira、Confluence、Bitbucket 和 Bamboo 产品的四个高危漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTuPwxnxpmkCJBDvQdgXGE5mTiczNFTAEC0GdNqSP1r4iaicRN8eee05yUhf6YOzBLulH1ia9Qg2LRuvg/640?wx_fmt=png "")  
  
  
其中，最严重的漏洞是CVE-2023-22513（CVSS评分为8.5），是位于 Bitbucket 中的一个远程代码执行漏洞，可影响机密性、完整性和可用性。认证攻击者可在无需用户交互的前提下利用该漏洞。该漏洞在 Bitbucket 8.0.0 版本中引入，影响8.14.0之前的版本。Bitbucket 8.9.5、8.10.5、8.11.4、8.12.2、8.13.1、8.14.0 和更新版本中修复了该漏洞。  
  
第二个漏洞CVE-2023-22512（CVSS评分7.5）是位于 Confluence Data Center 和 Server 产品中的拒绝服务漏洞。未认证攻击者可利用该漏洞，“通过临时或无限破坏联网的易受攻击主机的服务” 拒绝对资源的访问。该漏洞在 Confluence 5.6中引入，影响该产品8.5.0及之前版本。Atlassian 已在 Confluence 7.19.14和8.5.1中修复该漏洞。  
  
第三个漏洞CVE-2023-28709（CVSS评分7.5）是一个第三方依赖漏洞，可被攻击者用于“暴露环境中资产”。该漏洞存在于 Apache Tomcat 中，是因为另外一个漏洞CVE-2023-24998的补丁不完整造成的。该漏洞在 Bamboo 8.1.12中引入，已在 Bamboo 9.2.4 和 9.3.1中修复。建议更老旧版本用户更新至已修复版本。  
  
第四个漏洞是位于 Jira 中的CVE-2022-25647（CVSS评分7.5），可导致攻击者暴露资产以遭进一步利用。该漏洞在Jira 4.20.0中引入，已在4.20.25、5.4.9、5.9.2、5.10.1和5.11.0中修复。  
  
Atlassian 公司提到，“安全通告中的这些漏洞包括四个高危漏洞，已在产品新版本中修复，并于上个月发布。这些漏洞是通过我们的漏洞奖励计划和渗透测试流程以及第三方库扫描发现的。”该公司并未提到这些漏洞是否已遭在野利用。  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[第三方app受陷，Atlassian 数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515624&idx=3&sn=67fc0501190042defabcc173a6eb618f&chksm=ea948c82dde30594c6d827c3f9a2ec0f74bc3ac9f01de20c08188c4f469b2a74cbf9381d0a01&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Crowd 和 Bitbucket 产品中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514682&idx=2&sn=dc35e642f56cb043c698c74c4a7cc1db&chksm=ea948b50dde3024635cc241de37f67ec45fccba1bb52808e5a89a1908c6cd04233a2502e782c&scene=21#wechat_redirect)  
  
  
[立即修复！Atlassian Bitbucket 服务器易受严重的 RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513716&idx=1&sn=17534c8b961a4ef3a27b7ecdf4588568&chksm=ea94871edde30e08de08a258e2ba454e862dc7b989c93439978434f6141872e937b7f16615b0&scene=21#wechat_redirect)  
  
  
[Atlassian 修复严重的Confluence 硬编码凭据漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513005&idx=2&sn=65a9ae762a7954f9a33b371fd2aed816&chksm=ea9482c7dde30bd1bd79614e758e742a403975ff8cae09386f6fdd5615bc8176574e05c1b6e9&scene=21#wechat_redirect)  
  
  
[Atlassian 修复Jira 中的完全读取SSRF漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512767&idx=2&sn=a0b241acce83341531e098b976dc2d6c&chksm=ea9483d5dde30ac37e8cb4cb914a843a0ddc13924b0915e5518a0e2ebe4c6725758f476fb8fb&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/atlassian-security-updates-patch-high-severity-vulnerabilities/  
  
  
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
  
