#  谷歌推出新的KVM漏洞奖励计划，最高赏金25万美元   
Eduard Kovacs  代码卫士   2024-07-02 17:27  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMScDwDbicqqelIwhMSyOfp4VDm49xdxhbzwgNyoVTD68ibAWxPXlzqdbkm95VoqFLUPhOjxvMyIsS1w/640?wx_fmt=gif&from=appmsg "")  
  
**谷歌宣布推出基于Kernel 的虚拟机 (KVM) 管理程序漏洞奖励计划 kvmCTF，目的是助理找到和解决 KVM 管理程序中的漏洞，最高赏金25万美元。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMScDwDbicqqelIwhMSyOfp4VDMvVfaVM5v24oIGwhjlYu1IVCYJLIPhcXcvoHahLGzqCcrVlYSlvrQ/640?wx_fmt=gif&from=appmsg "")  
  
  
kvmCTF 计划类似于CTF活动。参与者需要能够在规定时间内访问托管在实验环境中的 guest VM，并尝试执行 guest-to-host 攻击。谷歌希望该项目有助于找到虚拟机逃逸、任意代码执行漏洞、信息泄露问题以及拒绝服务漏洞。  
  
谷歌在博客文章中提到，“攻击的目标必须是利用主机内核KVM子系统中的一个 0day。如成功利用，则攻击者将夺得一面旗子，证明他们成功利用该漏洞。”  
  
如参与者能找到完全的VM逃逸，则可获得赏金25万美元；如找到任意内存写利用，则获得10万美元；如找到任意内存读或相关的内存写利用，则获得5万美元；如找到拒绝服务攻击，则最高可获得2万美元；如找到相关的内存读漏洞，则最高可获得1万美元。  
  
KVM 广泛用于消费者和企业解决方案中，包括安卓和谷歌云平台等，而这也是谷歌希望增强其安全性的原因所在。  
  
更多信息，可参见：https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing.html?m=1  
。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌发布漏洞奖励计划和其它举措，保护AI安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517995&idx=2&sn=aa7c780dbbe15bdfa9149c612cc02a53&chksm=ea94b641dde33f57d58495235b0c8364876b2834bf5b00df2c2a91f9125634d621d15c9ac6d6&scene=21#wechat_redirect)  
  
  
[谷歌推出开源软件漏洞奖励计划，提振软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513721&idx=1&sn=9ccc0511cb8d6c7134eb54700130f1b7&chksm=ea948713dde30e0503874ed6e5ebcd5a90933ef86048fd21466e73431420b799a861f800164a&scene=21#wechat_redirect)  
  
  
[谷歌提高Linux内核漏洞奖励金，最高133337美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513581&idx=4&sn=f0294acd7ecf151a3b1ff864f5c3f5d5&chksm=ea948487dde30d9136344e6fc7af6c91b22d199edeaac3dc51a97671d397f00655b78d7af6eb&scene=21#wechat_redirect)  
  
  
[谷歌 Nest 和 Fitbit 漏洞奖励翻番](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511275&idx=3&sn=69dc3098fb1526769d7cc6e8bf65521c&chksm=ea949d81dde314976ec7b8a541042c17f2e3e56ea07ec29fe82fe3878599e94f494256ad4235&scene=21#wechat_redirect)  
  
  
[谷歌宣布 Linux Kernel、Kubernetes 0day 漏洞奖励加倍](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510538&idx=1&sn=a9a27b42e41b2806b88b7426cfa96d0b&chksm=ea949b60dde312761990cbeffc2d79d9c0c9f94ec83fb5a1a19f57729d3fb1451504afdc9e41&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/google-offering-250000-for-full-vm-escape-in-new-kvm-bug-bounty-program/  
  
  
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
  
