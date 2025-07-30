#  高通：速修复这三个已遭利用的 Adreno GPU 漏洞   
Ryan Naraine  代码卫士   2025-06-03 10:35  
  
其中  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**周一，手机芯片制造商高通提醒称，专业黑客已在利用三个新修复的 Adreno GPU 漏洞，高通正在督促电话制造商立即推出可用的修复方案。**  
  
  
高通并未提供这些攻击的详情，不过援引“谷歌威胁分析组织的指标”提到，三个漏洞（CVE-2025-21479、CVE-2025-21480和CVE-2025-27038）“或已遭有限的针对性利用”。该公司并未分享更多关于在野攻击的详情，谷歌也并未公开记录这些利用。“有限的针对性利用”的说辞表明这些利用可能与商用监控软件产品有关。  
  
高通发布2025年6月安全通告指出，这些漏洞的补丁已经在5月交付给原始设备制造商和电话制造商，高通强烈督促电话制造商“尽快”推送更新。高通提到，“请联系设备制造商获取关于特定设备的补丁状况。”  
  
在这三个漏洞中，两个被评级为“严重”，是位于GPU微码中的授权不当漏洞，可导致恶意命令损坏内存。这些漏洞的CVSS编号为8.6分。第三个遭利用的漏洞是位于 Adreno 驱动中的一个UAF漏洞，可从Chrome 触发，CVSS评分为7.5。  
  
高通发布多个“高危”补丁集，这些漏洞涵盖数据网络栈、WLAN HAL DoS 和一个蓝牙主机内存损坏问题，包含上述三个漏洞的补丁。高通还发布了位于DSP服务、音频、计算机视觉和摄像头驱动中的漏洞补丁。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[安卓间谍软件 NoviSpy 利用高通6个0day感染设备](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521826&idx=2&sn=2e115cf641ac90636ca05cde8df5fa09&scene=21#wechat_redirect)  
  
  
[高通修复已遭利用的高危0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520994&idx=2&sn=ef89231ad1b43e2679e43b82ddb620f4&scene=21#wechat_redirect)  
  
  
[全球约30%的智能手机受高通新漏洞影响，打补丁状况不明](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504006&idx=2&sn=5e3be0f6a913cde1548583ff6f77c3d2&scene=21#wechat_redirect)  
  
  
[近一半的智能手机受高通 Snapdragon 漏洞影响](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494521&idx=4&sn=fa7888169d1be68fd1af317a39f14f42&scene=21#wechat_redirect)  
  
  
[重大漏洞导致高通 QSEE 组件瘫痪，所有安卓和 IoT 设备可遭完全控制](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489812&idx=1&sn=846cfa78416c05d49fee4b37e9dd1348&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/qualcomm-flags-exploitation-of-adreno-gpu-flaws-urges-oems-to-patch-urgently/  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
