#  PHPFusion 开源 CMS 中存在严重漏洞   
Jai Vijayan  代码卫士   2023-09-06 20:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**安全研究员在广泛使用的开源内容管理系统 PHPFusion CMS 中发现了一个严重漏洞，目前尚无补丁。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRrBYGl351n6xZqZFg3ZY8bkibnOiaibaoUVTASNBU1BVgNkY5hOWzlgR2g/640?wx_fmt=png "")  
  
  
该漏洞是一个验证的本地文件包含漏洞，编号为CVE-2023-2453。如攻击者可在目标系统的一个已知路径上上传恶意构造的 “.php” 文件，则可导致远程代码执行后果。  
  
这是新思公司最近在 PHPFusion 中发现的两个漏洞之一。另外一个漏洞是CVE-2023-4480，它是位于该CMS 中的一个中危漏洞，可导致攻击者读取受影响系统上的文件内容，并将文件写入任意位置。这些漏洞位于 PHPFusion 9.10.30 及更早版本中。目前两个漏洞均无补丁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRycicvicD3qjAztoFtUuWY0jq71kggt3Xxjwjgvd17wt3ZXnViaXlXGmLg/640?wx_fmt=png "")  
  
**无补丁**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRyrMfZ0uHibaicyq2LBMn5hHKB0XuDuCbbqxa0TjB1nmiaAh1qEWDXzDag/640?wx_fmt=png "")  
  
  
  
新思公司表示，多次尝试通过邮件、漏洞披露流程、GitHub、社区论坛联系 PHPFusion 的管理员但均未果。目前PHPFusion 尚未就此置评。  
  
PHPFusion 是一款早在2003年就存在的开源CMS。尽管它并不如其他内容管理系统如WordPress、Drupal 和 Joomla 那样有名，但目前全球约1500万个网站都在使用它。中小型企业通常用它来构建在线论坛、社区驱动网站以及其它在线项目。  
  
新思指出，CVE-2023-2453 是因为某些文件类型对已污染文件名称的清洁不当造成的。攻击者可利用该漏洞在任意的 PHPFusion 服务器上上传并执行任意 .php 文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRycicvicD3qjAztoFtUuWY0jq71kggt3Xxjwjgvd17wt3ZXnViaXlXGmLg/640?wx_fmt=png "")  
  
**利用条件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSS3HRdicXibDnfEXjP3fLlMRyrMfZ0uHibaicyq2LBMn5hHKB0XuDuCbbqxa0TjB1nmiaAh1qEWDXzDag/640?wx_fmt=png "")  
  
  
  
发现该漏洞的软件工程师 Matthew Hogg 提到，“利用该漏洞只需两个要求”，一是攻击者需要能够至少以低权限账户认证，另外一个是需要了解易受攻击的端点。他提到，“如能满足这两个条件，恶意人员将能够构造 payload，利用该漏洞。”  
  
该公司的漏洞管理工程师 Ben Ronallo 提到，攻击者需要找到将恶意构造的 .php payload 上传到易受攻击系统上的任意位置十分重要，“攻击者需要查看 PHPFusion 的源代码，识别易受攻击的端点。”  
  
利用该漏洞后攻击者能做的事情取决于与 PHPFusion 用户账户关联的权限。例如，能够访问管理员凭据的攻击者能够读取底层操作系统上的任意文件。他提到，“在最坏的情况下，如果攻击者能够有办法将 payload 文件上传到目标，则能够实现远程代码执行。这两种情况均可导致敏感信息被盗，后者可能导致易受攻击服务器遭控制。”  
  
同时，严重性更低的另一个漏洞CVE-2023-4480与Fusion 文件管理器组件中的一个过时依赖有关，该组件可通过该 CMS 的管理员面板访问。具有管理员或超级管理员权限的攻击者可利用该漏洞披露易受攻击系统上的文件内容，或者获奖某些文件类型写入该服务器文件系统上的已知路径。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源CMS TYPO3中存在XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513988&idx=2&sn=d8e2aa2199ecfa383521908c1073c29b&chksm=ea9486eedde30ff81f3dd92049688847d298f700e6c02f09be03797789e7985c8a14915576a5&scene=21#wechat_redirect)  
  
  
[开源的dotCMS 内容管理软件中存在严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511649&idx=2&sn=b8446991d9e5831092d721d0b28041e9&chksm=ea949f0bdde3161d9d800734ed35396a6f8b72908a329f1e9e1b42a8707f0848db05481b542f&scene=21#wechat_redirect)  
  
  
[热门开源CMS平台 Umbraco 中存在多个安全漏洞，可使账户遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510233&idx=3&sn=a3b6ac9c3a90291e1ce56a9111954282&chksm=ea9499b3dde310a51a41d289f8a10f64e2c5ebf719f58180cb79ed8ed31461d68341b1aa6ab4&scene=21#wechat_redirect)  
  
  
[开源 CMS Drupal 修复 XSS 和开放重定向漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493187&idx=2&sn=8ac5c62090bbee44166832232e092223&chksm=ea94d729dde35e3f802678198384d8ca46194058f56e4fd6e4590507ce5892ffdf214acf9046&scene=21#wechat_redirect)  
  
  
[WordPress CMS 平台存在严重的DoS 缺陷影响几乎所有版本 厂商拒绝修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486392&idx=1&sn=5f7d378ae313a0a9fc1faf6b099b7af2&chksm=ea973ad2dde0b3c4836c59f6c4eba091d6fda8ecf8cbe66de3a345a8c9112d740458f5787b65&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.darkreading.com/application-security/researchers-discover-critical-vulnerability-in-phpfusion-cms  
  
  
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
  
