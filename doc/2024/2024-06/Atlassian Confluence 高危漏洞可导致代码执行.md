#  Atlassian Confluence 高危漏洞可导致代码执行   
Darkreading  代码卫士   2024-06-05 17:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**SonicWall Capture Labs 的研究团队发现了 Atlassian Confluence Data Center and Server 中的一个远程代码执行漏洞。**  
  
该漏洞的编号是CVE-2024-21683，CVSS评分为8.3，可导致认证攻击者执行任意代码。要利用该漏洞，攻击者必须具有对易受攻击系统的网络访问权限，并拥有增加新的宏语言的权限。研究人员提到，要利用该漏洞，攻击者可将包含恶意代码的JavaScript 语言文件上传到“配置代码宏＞增加新语言”。  
  
SonicWall 为客户发布了两个签名以及妥协指标，以防被利用：IPS: 4437 Atlassian Confluence Data Center and Server RCE 和 IPS: 4438 Atlassian Confluence Data Center and Server RCE 2。目前已存在CVE-2024-21683的PoC利用代码。  
  
研究人员强烈建议用户将实例升级至最新可用版本，因为 Confluence Server 在维护组织机构知识库和其它重要信息中发挥重要作用。Atlassian Confluence 漏洞一般而言备受网络犯罪分子的青睐，因为该平台深入网络环境并可用于跨企业协作、工作流和软件开发。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Atlassian 发布20多个漏洞，含严重的 Bamboo 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519117&idx=2&sn=c0c8035f5617c6f76c73e71b9e73f04f&chksm=ea94bae7dde333f1efbbaeff72b89df023bbc2e6d408df713a753e060c09ff210656828d17d9&scene=21#wechat_redirect)  
  
  
[Atlassian Confluence 远程代码执行漏洞(CVE-2023-22527)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518678&idx=1&sn=aedf682361f621f14474e78244d3242e&chksm=ea94b8bcdde331aa278b8d6c8fe7f1df9ec253aa21e960355a967894be85796756b54e173c95&scene=21#wechat_redirect)  
  
  
[Atlassian 修复多款产品中的多个严重RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518302&idx=1&sn=9ede9c29a5c7c063571222672e754926&chksm=ea94b934dde330222c90b770d277247b3ad535c2b85b8082228c17630922ff9ea123ab19691f&scene=21#wechat_redirect)  
  
  
[Atlassian 提醒注意严重的 Confluence 漏洞，可导致数据丢失](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518036&idx=1&sn=ad96c9dc39840b68b765672413fcb367&chksm=ea94b63edde33f289d197760bd0839cbaaa57edd6a2e5e6d5e9749ce290abfea667c37d2ba69&scene=21#wechat_redirect)  
  
  
[Atlassian 紧急修复已遭利用的 Confluence 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517813&idx=2&sn=6a3b7d66586da1ad6c1cb57b1db81155&chksm=ea94b71fdde33e09a176e23f52637a496b5d244d21adece15ff30273b5a330a21fea95f10aff&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/vulnerabilities-threats/atlassian-confluence-high-severity-bug-allows-code-execution  
  
  
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
  
