#  黑客利用高危 Openfire 漏洞加密服务器   
Bill Toulas  代码卫士   2023-09-27 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**黑客正在利用 Openfire 通讯服务器中的一个高危漏洞，以勒索软件加密服务器并部署密币挖矿机。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRoAVk4tk5bsP05wM0PaV8EibOEpKIBWricSqwKNicH4XsePUY72wfNzI47fsCXRTUprm9MJ2MZOtI3w/640?wx_fmt=gif "")  
  
  
Openfire 是一款广泛使用的基于 Java 的开源聊天 (XMPP) 服务器，下载次数已达900多万次，广泛应用于多平台的安全聊天通信中。该漏洞的编号是CVE-2023-32315，是影响 Openfire 管理面板的认证绕过漏洞，可导致未认证攻击者在易受攻击服务器上创建新的管理账户。  
  
攻击者使用这些账号安装恶意 Java 插件（JAR 文件），执行通过GET和POST HTTP 请求接收的命令。该漏洞影响自2015年发布的 3.10.0 至4.6.7以及4.7.0到4.7.4的所有版本。  
  
尽管 Openfire 已在2023年五月发布的版本4.6.8、4.7.5和4.8.0中修复了该漏洞，但VulCheck 公司报道称，截止到2023年8月中旬，超过3000台 Openfire 服务器仍然在运行易受攻击的版本。  
  
Dr. Web也发现了该漏洞遭活跃利用的迹象。Dr. Web 在调查一起勒索攻击活动时发现了首例活跃利用。攻击者利用该漏洞在 Openfire 上创建新的管理员账户、登录并安装可运行任意代码的恶意 JAR 插件。Dr. Web 和客户发现其中一些恶意 JAVA 插件，包括 helloworld-openfire-plugin-assembly.jar、 product.jar 以及bookmarks-openfire-plugin-assembly.jar。  
  
Dr.Web 设置蜜罐捕获该恶意软件时还捕获到在野利用的其它木马。第一个 payload 是基于 Go的密币挖矿木马 Kinsing。其操纵人员利用CVE-2023-32315创建名为 “OpenfireSupport” 的管理员账户，之后安装了名为 “plugin.jar”的恶意插件，用于捕获挖矿机payload 并将其安装在服务器上。在另外一个案例中，攻击者安装了基于C的 UPX 封装后门，它也遵循相似的感染链。第三个攻击场景是，恶意 Openfire 插件用于获取受陷服务器的信息，尤其是特定的网络连接、IP地址、用户数据和系统的内核版本。  
  
Dr. Web 已观测到利用CVE-2023-32315的四个不同的攻击场景，因此应立即安装补丁。  
  
  
**未知的勒索软件**  
  
  
  
  
多名客户报道称其 Openfire 服务器遭勒索软件加密，其中一名客户称这些文件被通过 .locked1 扩展加密。  
  
OpenFire 管理员支出，“我是一名使用Openfire开源软件的韩国运营商。虽然我用的是 opensire 4.7.4-1.noarch.rpm，但突然有一天 /opt/openfire（openfire 安装路径）中的所有文件都变成了 .locked1 扩展。”  
  
自2022年期，威胁行动者已通过 .locked1 扩展的勒索软件加密被暴露的 web 服务器。BleepingComputer 报道称，在6月份就发现了该勒索软件加密 openfire 服务器的情况。  
  
目前尚不清楚，该勒索软件是否是这些攻击的幕后黑手，不过勒索金通常都较少，从0.09到0.12个比特币不等（2300到2500美元）。该威胁行动者似乎不仅针对 Openfire服务器，而是针对任何易受攻击的 web 服务器。因此尽快应用所有安全更新至关重要。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[数千台未修复 Openfire XMPP 服务器仍易受高危漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517466&idx=1&sn=56ec3d83af97ad62084124c205e2349b&chksm=ea94b470dde33d66e66beaa6ad53e44d25babf2e6c0517f8b86135be8ba15399ba13dcea6b78&scene=21#wechat_redirect)  
  
  
[索尼所有系统再遭勒索攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517746&idx=2&sn=e94509cd28703e663d3e8a24d26f2b1c&chksm=ea94b758dde33e4ec48eabdc2e3da5a379ae98d58dcd8f0b3f6f928c12e7e0f5b6bbd0ad25bd&scene=21#wechat_redirect)  
  
  
[严重漏洞可导致TeamCity CI/CD 服务器遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517746&idx=1&sn=0075949af101ed923a30865094aa5b5f&chksm=ea94b758dde33e4eed497321fbcde1b5e775602f446cd3c4b5bbc8d0aba92f2bfb4067686bca&scene=21#wechat_redirect)  
  
  
[黑客利用 MinIO 存储系统漏洞攻陷服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517551&idx=2&sn=8ffd41e1e450dfc4af6a55aa0de56c8f&chksm=ea94b405dde33d1371b97b39c7238f48c9e1e675f37dbcae210f7f4f982b1f61f702d9f67ba4&scene=21#wechat_redirect)  
  
  
[开源的IT监控软件Icinga web 中存在两个漏洞，可被用于攻陷服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511800&idx=1&sn=0f335367280974447c6dea4d856bc39b&chksm=ea949f92dde31684607d46322cc43b6250fcfe1d328aee28eae6304ec2e5d82577b9209cd75e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/hackers-actively-exploiting-openfire-flaw-to-encrypt-servers/  
  
  
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
  
