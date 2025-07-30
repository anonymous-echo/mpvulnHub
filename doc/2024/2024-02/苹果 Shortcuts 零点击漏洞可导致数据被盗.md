#  苹果 Shortcuts 零点击漏洞可导致数据被盗   
Nathan Eddy  代码卫士   2024-02-23 18:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**苹果 Shortcuts 中存在一个危险漏洞 (CVE-2024-23204)，可导致攻击者在无需获得权限的情况下访问设备的敏感数据。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQezqMGSrgdqc1eU7bXLtBxxjNh0cAm4reSbtlHS1b4ib0iby5gV1xGCtfiaa4K6vNLCKjH2BnHQDXDA/640?wx_fmt=gif&from=appmsg "")  
  
  
苹果的 Shortcuts 应用为 macOS 和 iOS 而设置，旨在将任务自动化。对于企业而言，该应用可使用户创建宏在设备上执行具体任务，之后将它们组合到工作流中，用于 web 自动化、智慧工厂功能等。随后可通过 iCloud 和其它平台与同事和合作伙伴在线分享。  
  
Bitdefender 发布分析指出，该漏洞可使攻击者构造恶意 Shortcuts 文件，绕过苹果的“透明、同意和控制 (TCC) ”安全框架。而该框架用于确保应用在访问某些数据或功能前明确请求用户获得权限。  
  
这就意味着当有人将恶意捷径增加到库时，可悄悄盗取敏感数据和系统信息，而无需从用户获得访问权限。研究人员在 PoC 利用中展示了他们能够提取加密图像文件中的数据。  
  
报告提到，“随着 Shortcuts 成为用于有效任务管理广为使用的特性，该漏洞引发了关于通过多种分享平台传播恶意捷径的担忧。”  
  
该漏洞无需权限即可遭远程利用，为运行 macOS Sonoma 14.3、iOS 17.3和iPadOS 17.3的 macOS 和 iOS 设备造成威胁，CVSS评分为7.5。苹果已修复该漏洞，并提到，“我们督促用户确保运行 Apple Shortcuts 软件的最新版本。”  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQezqMGSrgdqc1eU7bXLtBxYjlTiaQuFLGMNicfFqYeU8ia3Nxjiawyy2b2tE7x4ICPDX1rtD55INJZwg/640?wx_fmt=gif&from=appmsg "")  
  
**苹果安全漏洞：变得更加常见**  
  
  
  
去年10月份，Accenture 发布报告指出自2019年以来，暗网上针对 macOS 的威胁行动者的数量增加了10倍，且这个趋势仍将持续。  
  
这一研究成果和复杂的用于绕过苹果内置检测的 macOS 信息窃取器的出现一致。卡巴斯基研究人员最近发现针对比特币和 Exodus 密币钱包的 macOS 恶意软件。该恶意软件以受攻陷版本替换合法应用。  
  
漏洞也不断出现，使得初始访问更为容易。例如，今年早些时候，苹果修复了位于 Safari 浏览器 WebKit 引擎中的一个 0day 漏洞 (CVE-2024-23222)。该漏洞由类型混淆错误引发。  
  
为避免恶意后果，该报告强烈建议用户将 macOS、iPadOS和watchOS 设备更新至最新版本，谨慎执行来自不可信来源的捷径并定期检查苹果发布的安全更新和补丁。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab 提醒注意严重的零点击账户劫持漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518669&idx=1&sn=e9e78678e6c35cd6c0c37b638d5a988c&chksm=ea94b8a7dde331b16bdf8306a2700a04ea240bc5baa204b72ab3c9664a58b77c6fc92b1841f4&scene=21#wechat_redirect)  
  
  
[Outlook 漏洞链可导致零点击 RCE](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=3&sn=cb664e1652c64f2620d83f4d174c33a2&chksm=ea94b991dde33087d376a41410a6a209414e7c0ef860e70eaba6105e3021c714a6b3bdd2a8df&scene=21#wechat_redirect)  
  
  
[iOS 用户遭零点击 root 权限恶意软件攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=3&sn=98e4e8c8a8f861765f6f700cd7f559e4&chksm=ea94b083dde33995c70d095c4c98acdfae6b5e2f7edf6bd83e569b1d62eb9feb215671dab293&scene=21#wechat_redirect)  
  
  
[NSO集团2022年至少使用了3个 iOS 零点击 exploit](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516269&idx=2&sn=ce98d0e24d86dc1299d184713687b43d&chksm=ea94b107dde33811dc2662ffe815d6035779b7303082f256c0cdb7b0bdec0bd9b0552a29a5eb&scene=21#wechat_redirect)  
  
  
[以色列监控公司 QuaDream 利用零点击 exploit 攻击高风险 iPhone](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516244&idx=2&sn=654d0ae79529c38984d055c4803ff62c&chksm=ea94b13edde338280e22bbdf455150dbe5eb12bd51fdf528ccbfbd9db4d3a7a5b3455ce460a9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.darkreading.com/application-security/zero-click-apple-shortcuts-vulnerability-allows-silent-data-theft  
  
  
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
  
