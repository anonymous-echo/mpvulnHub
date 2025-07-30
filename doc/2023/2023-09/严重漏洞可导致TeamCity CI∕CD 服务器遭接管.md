#  严重漏洞可导致TeamCity CI/CD 服务器遭接管   
Ionut Arghire  代码卫士   2023-09-26 17:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**TeamCity CI/CD 服务器中存在一个严重漏洞，可在无需认证的情况下遭远程利用，执行任意代码并获得对易受攻击服务器的管理控制权限。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTMiajFjQr8SibGokAWhBg0hyI4VLYhd5iauNEDU6a5Jt8SDUNy3EmiczZZVHW9EvLiab3ExicstkbKNwjQ/640?wx_fmt=gif "")  
  
  
TeamCity 由 JetBrains 开发，是适用于本地和云的通用构建管理和可持续集成平台。CVE-2023-42793（CVSS评分9.8）是影响 TeamCity 本地版本的认证绕过漏洞。  
  
发现该漏洞的公司 Sonar Source 提到，攻击者可通过HTTP(S) 连接利用该漏洞，且成功利用无需用户交互。该公司提到，“这可导致攻击者不仅窃取源代码还能够存储服务机密和私钥。更糟糕的是，通过访问构建流程，攻击者可注入恶意代码，攻陷软件发布的完整性并影响所有下游用户。”Sonar 公司提到，攻击之所以很可能发生，是因为CI/CD服务器如 TeamCity 可自动化处理软件开发流程，即可访问组织机构的源代码和与构建、测试和部署流程相关联的其它敏感信息。  
  
JetBrains 表示，所有TeamCity 本地2023.05.3及以下版本受该漏洞影响。TeamCity 云版本不受该漏洞影响。该漏洞已在 TeamCity 2023.05.4中修复。JetBrains 还为 TeamCity 8.0及以上版本发布安全补丁插件，但表示不打算向后兼容该修复方案。  
  
JetBrains 解释称，“该安全补丁插件将仅修复上述提到的RCE漏洞。我们一直推荐用户将服务器升级到最新版本，接收很多其它安全更新带来的益处。” 用户应立即对可从互联网访问的 TeamCity 服务器打补丁或者在补丁发布前使其不可从互联网访问。  
  
JetBrains 和 Sonar 公司表示，该漏洞的详情尚未发布。Sonar 公司提到，该漏洞易于利用，很可能会看到在野利用的情况。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CI/CD平台CircleCI督促客户修改机密信息](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515211&idx=1&sn=f23e5a2a184fe7df7db89c38459ddaa2&chksm=ea948d21dde30437f04f788f01692b17a55370ce7a6f9e967946dcda1a29a34cc4a0fab32625&scene=21#wechat_redirect)  
  
  
[热门开源CI/CD解决方案 GoCD 中曝极严重漏洞，可被用于接管服务器并执行任意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508832&idx=1&sn=bac2576345afca50ce02e42e2b32162b&chksm=ea94920adde31b1c9de180a18739a4121c8a470d0bf9c29051e309927a9fec05601b1e7d7596&scene=21#wechat_redirect)  
  
  
[Apache Superset 漏洞导致服务器易遭RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=3&sn=f9b4133a88826774ba2370f315ddb483&chksm=ea94b4f5dde33de31fafd6622cb2b37398ceb935de72fe956bfdb5dc3d1b4a4ae61195437351&scene=21#wechat_redirect)  
  
  
[数千台未修复 Openfire XMPP 服务器仍易受高危漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517466&idx=1&sn=56ec3d83af97ad62084124c205e2349b&chksm=ea94b470dde33d66e66beaa6ad53e44d25babf2e6c0517f8b86135be8ba15399ba13dcea6b78&scene=21#wechat_redirect)  
  
  
[PaperCut高危漏洞可使未修复服务器受RCE攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517335&idx=1&sn=fb6f828cad2dd147b64eb18c25e34e7b&chksm=ea94b5fddde33ceb6bbdf2cd3e5cda0f1103d555edec4b0e6008b76a45ecf4d51beda67e6305&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/in-the-wild-exploitation-expected-for-critical-teamcity-flaw-allowing-server-takeover/  
  
  
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
  
