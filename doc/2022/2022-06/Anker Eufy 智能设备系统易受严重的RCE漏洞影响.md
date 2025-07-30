#  Anker Eufy 智能设备系统易受严重的RCE漏洞影响   
Bill Toulas  代码卫士   2022-06-17 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxFSUORBBuUtbhq53ibjE2c8z1NzWaiaRKZrK0pahtib0YzibCMwMmVnUCvw/640?wx_fmt=png "")  
  
Anker公司的 Eufy Homebase 2 智能家居摄像头系统易受三个漏洞影响，其中一个是严重的RCE漏洞。  
  
  
  
Homebase 2 是Anker Eufy 智能家庭设备的视频存储和网络网关。这些设备包括视频门铃、室内安全摄像头、智能锁、报警系统等。  
  
Homebase 是 Eufy 设备的中心站，和云相连，提供增强这些产品功能的服务，使用户能够通过一款app进行远程控制。  
  
思科 Talos 团队的安全研究员表示，Homebase 2 受三个潜在的危险漏洞影响，可造成隐私入侵、服务破坏和代码执行后果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxcoGkFjdqUktU90aTSOP8YOYH0zibcdjowWJAc07wDjuTMRmrSibvELQw/640?wx_fmt=gif "")  
  
**三个严重缺陷**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxSicWibaXEsrZIiaQalA7TXgAUKcNUFrVibUGdaqxiaIynRxfxev8IFIPsCw/640?wx_fmt=png "")  
  
  
  
其中最严重的漏洞CVE-2022-21806 是RCE漏洞（CVSS评分10分），通过向目标设备发送特殊构造的网络数据包即可触发。该漏洞的根因在于Hombase 用于接受网络中特殊格式信息的内部服务器功能中的释放后使用问题。  
  
第二个漏洞是CVE-2022-26073，它是高危漏洞（CVSS评分7.4），也可通过发送特殊构造的网络数据包的方式被远程触发。利用该漏洞可使设备位于重启状态，因此最主要的后果是拒绝服务。然而，在影响家庭安全系统的上下文中，在一些场景下该缺陷可轻易被恶意人员利用。  
  
第三个漏洞是高危的CVE-2022-25989（CVSS评分7.1），它是一个认证绕过漏洞，通过特殊构造的 DHCP 数据包即可触发，导致Homebase 将流量发送到外部服务器。  
  
攻击者可利用该缺陷从联网摄像头设备中接收视频内容并监控设备所有人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxcoGkFjdqUktU90aTSOP8YOYH0zibcdjowWJAc07wDjuTMRmrSibvELQw/640?wx_fmt=gif "")  
  
**修复方案已发布**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxSicWibaXEsrZIiaQalA7TXgAUKcNUFrVibUGdaqxiaIynRxfxev8IFIPsCw/640?wx_fmt=png "")  
  
  
  
思科Talos 团队在发布前将这些漏洞告知 Anker 公司，使后者能够通过安全更新的方式予以修复。  
  
Anker 发布固件版本3.1.8.7和3.1.8.7h 修复了这些漏洞，并在2022年4月发布。这意味着多数 Homebase 2 设备在购买后如未更新固件，则易受上述缺陷影响。  
  
思科研究员还发布了利用这些漏洞的技术详情，这些详情可能被恶意人员用于发动实际的攻击。更新 Eufy 设备固件的最容易的方法是通过app，可根据支持页面操作。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
**推荐阅读**  
  
[联网智能设备安全态势季度报告（2021年第2季度）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508375&idx=2&sn=f5baf37d1e44f891512723bf698862da&chksm=ea9490fddde319eb4ebcf81508e95c8b154da9b3f2214588db82323933ba73c46b7be917ac88&scene=21#wechat_redirect)  
  
  
[微软披露25个漏洞 BadAlloc，至少影响数十亿智能设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503961&idx=2&sn=14789bab04df9c158f85e6ee34ae12fc&chksm=ea94e133dde36825c2acad70510b59eee95978d739f017526355ca9713084b85dfd20dbff19c&scene=21#wechat_redirect)  
  
  
[有人劫持智能设备报假警，并直播出警画面](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499872&idx=5&sn=07590eedb2f8b4d829854bd75f5d7d6d&chksm=ea94f10adde3781cbafe183c9eb86b15192bc7c0089d9d389e35365475c17bab2fd5af9ebbef&scene=21#wechat_redirect)  
  
  
[多个Wyze 摄像头漏洞可导致攻击者接管设备并访问视频](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511227&idx=4&sn=6f352ab9a489722b06e9f7b65f2f1ebd&chksm=ea949dd1dde314c7f99397ef312b0074bbd05b5067a602260b54dfcdea9b0b7b511b7d4dc228&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/anker-eufy-smart-home-hubs-exposed-to-rce-attacks-by-critical-flaw/  
  
  
题图：Pixabay License  
  
  
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
