#  微软称 SysAid IT 支持软件 0day 遭利用   
THN  代码卫士   2023-11-10 17:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**微软称威胁组织 Lace Tempest 利用SysAid IT 支持软件中的一个0day 发动数量有限的攻击活动。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRatMH6nIPiassBopb2ZA2thdhMoLY7icZ0OSmicnmtYmwn8EnibUTEaPMD1F2Ju9gXdic8DJicJaXo0mAg/640?wx_fmt=png "")  
  
  
Lace Tempest 因分发 CI0p勒索软件而为人所知，此前曾利用 MOVEit 和 PaperCut 服务器中的 0day。这次该组织利用的 0day 是路径遍历漏洞CVE-2023-47246，可导致在本地版本实现代码执行后果。SysAid 已在 23.3.36 版本中修复该漏洞。  
  
微软指出，“利用该漏洞后，Lace Tempest 通过 SysAid 软件发布命令，为Gracewire 恶意软件传播恶意软件加载器。后续一般是手动活动，包括横向移动、数据盗取和勒索软件部署。”  
  
SysAid 提到，威胁组织将包含一个 web shell 和其它 payload 的 WAR 文档上传到 SysAid Tomcat web 服务的 webroot 中。该 web shell 除了向受陷主机提供后门访问权限外，还被用于传播旨在执行用于加载 Gracewire 的加载器的 PowerShell 脚本。攻击者还部署了第二个 PowerShell 脚本，用于擦除部署恶意 payload 的证据。  
  
另外，该攻击链还使用 MeshCentral Agent 和 PowerShell 来下载和运行合法的利用后框架 Cobalt Strike。  
  
强烈建议使用 SysAid 的组织机构尽快应用补丁以阻击潜在的勒索攻击并在打补丁前扫描环境中的利用迹象。  
  
前不久，FBI 提醒称，勒索软件攻击者正在攻击第三方厂商和合法系统攻击来攻陷企业。FBI 提到，“截止到2023年6月，Silent Ransom Group（也被称为 Luna Moth）实施了回调钓鱼数据盗取和勒索攻击，他们在钓鱼尝试中为受害者发送电话号码，这种钓鱼活动一般和受害者的账号费用相关。”如受害者上钩并呼叫所提供的电话号码，则恶意人员则会诱骗他们通过之后邮件提供的链接安装合法的系统管理工具。之后攻击者利用该管理工具安装其它遭修改的合法软件，攻陷本地文件和网络共享设备、提取受害者数据并勒索企业。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[ZDI称微软 Exchange 出现4个新0day，可导致RCE和数据被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518068&idx=1&sn=604c9c5bff720e69d48c8a4c67adf491&chksm=ea94b61edde33f08c5b1621f39b640a67e73881625fe41ee1199403eda4c57b6795f42a34e73&scene=21#wechat_redirect)  
  
  
[补丁星期二：微软、Adobe和Firefox纷纷修复已遭利用的 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517643&idx=1&sn=83e85b6b9bf3a9f0cf0c1843c9589950&chksm=ea94b4a1dde33db74b2b9c5ff5da439c9a2169fcab51d215bdc495affe02787d31ab6bcf7b98&scene=21#wechat_redirect)  
  
  
[微软7月补丁星期二修复132个漏洞：5个已遭利用0day且1个无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517016&idx=1&sn=5074282ae6c24bac3355b40d1cabb8fa&chksm=ea94b232dde33b24e9adff41dd364497012cd4fe06f43ac2e6579c5f297ce1443c3c745b757b&scene=21#wechat_redirect)  
  
  
[微软将花近一年的时间才能修复这个 Secure Boot 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516473&idx=1&sn=f56859b3fc89bfc1ea259f355d5ea57b&chksm=ea94b053dde33945ba3fd2c0d75213db0b00c2d06a6798292b97054c90cd86bbf0e56d7f1c5e&scene=21#wechat_redirect)  
  
  
[微软补丁星期二修复6个已遭利用的0day和ProxyNotShell 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514441&idx=1&sn=a687462eb551d63fbb672860005a9ac6&chksm=ea948823dde30135c59d68023becb7756a805bf09a7b4194b440161543de8d40661c97ee9531&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/11/zero-day-alert-lace-tempest-exploits.html  
  
  
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
  
