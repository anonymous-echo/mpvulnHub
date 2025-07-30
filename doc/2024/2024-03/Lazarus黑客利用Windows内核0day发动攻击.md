#  Lazarus黑客利用Windows内核0day发动攻击   
THN  代码卫士   2024-03-01 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**臭名昭著的黑客组织 Lazarus 利用最近修复的Windows Kernel 0day 获得内核级别的访问权限并禁用受陷主机上的安全软件。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT4ecvicWDAxFv5YWN6UwicQmtOEeSxruyNEqFGUnR3y6YGmWGSkeQJpTNx8cac9OhnaxMjwkm8WLYA/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞是CVE-2024-21338（CVSS评分7.8），它可导致攻击者获得系统权限，已由微软在2月补丁星期二中修复。微软指出，“要利用该漏洞，攻击者受陷必须登录系统，之后运行一个特殊构造的应用利用该漏洞并控制受影响系统。”  
  
虽然在发布更新时并未有迹象表明CVE-2024-21338已遭活跃利用，但微软在周三将漏洞的“可利用性评估”改为“检测到利用”。目前尚不清楚攻击何时发生，但据悉该漏洞在 Windows 10 1703 (RS2/15063) 版本中引入，而也是在该版本中首次实现了 0x22A018 IOCTL（输入/输出控制）句柄。  
  
Avast 公司发现了该漏洞的在野 admin-to-kernel 利用，表示通过武器化该漏洞实现内核读/写原语可使 Lazarus 组织“在仅数据的 FudModule rootkit的更新版本中执行直接的内核对象操纵。”  
  
FudModule rootkit 由ESET 和 AhnLab 公司首次在2022年10月报告，它能够通过 BYOVD 攻击禁止对受感染主机上的所有安全解决方案进行监控。在这类攻击中，攻击者植入易受已知的或0day漏洞攻击的驱动来提升权限。  
  
最近发生的攻击活动之所以影响重大是因为它“利用已知安装在目标机器上的驱动中的 0day，超过了 BYOVD的范畴”。该驱动是 appid.sys，它对于负责应用控制的 Windows 组件 AppLocker 的运行至关重要。  
  
Lazarus 组织利用 CVE-2024-21338执行任意代码的方式绕过了所有安全检测并运行了 FudModule rootkit。安全研究员 Jan Vojtěšek 表示该恶意软件仍在活跃开发状态，“FudModule 仅松散地集成到 Lazarus 恶意软件生态系统中，Lazarus 对于使用该 rootkit 非常谨慎，仅在适当情况下按需部署。”  
  
除了禁用系统记录器绕过检测外，FudModule 还关闭了具体的安全软件如 AhnLab V3 Endpoint Security、CrowdStrike Falcon、HitmanPro 和微软 Defender Antivirus。  
  
这一攻击说明朝鲜黑客组织的技术复杂度上了一个台阶，它不断迭代武器库以改进隐秘性和功能，同时阻止检测，为追踪增加难度。而Lazarus 组织对跨平台的关注点也得到了证实：它利用一个恶意日历会议邀请链接偷偷在苹果 macOS 系统上安装恶意软件。  
  
Vojtěšek 表示，“Lazarus 组织仍然是最为多产和长久的APT组织。FudModule rootkit就是最新的证明，是它武器库中最为复杂的工具之一。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[英韩：Lazarus 黑客组织利用安全认证软件 0day 漏洞发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518225&idx=2&sn=0c496ddfdfec8c17e1344333f0c218f6&chksm=ea94b97bdde3306d6bc1249b0087f09b8c0a192157a52d43e8f6b5b08e18465335d8518ce100&scene=21#wechat_redirect)  
  
  
[微软：Lazarus 黑客组织发动供应链攻击，攻陷 CyberLink 公司](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518210&idx=1&sn=3c6b327672ccb8c0b44cae5a8fc02e20&chksm=ea94b968dde3307e207d33f8f67304380f153cc3002f0d518d15331016a32e277493084c86fe&scene=21#wechat_redirect)  
  
  
[GitHub 提醒 Lazarus 黑客组织利用恶意项目攻击开发人员](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517127&idx=2&sn=18d95fca91d5d3e707a2b97d82c043f3&chksm=ea94b2addde33bbb3417005732d1595e151e3bf9cdd4f1a6e4ffc8cea828afc2e4b65a7f88d8&scene=21#wechat_redirect)  
  
  
[微软：Lazarus 组织正在利用开源软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514100&idx=1&sn=3faef3e49fb3de0120f975906006988f&chksm=ea94869edde30f8849dbd8938399e22005f34a444aefd4486ec68b0fc11d40ad7325c5e4a0fa&scene=21#wechat_redirect)  
  
  
[人设倒了扶起来：Lazarus 组织利用含木马的IDA Pro 攻击研究员](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509081&idx=2&sn=9889f9181752e980515c8c7c2a854be5&chksm=ea949533dde31c258def41ae84b713ba6ac32ec1c43bcd70b5c464ab03a628aa20e3cb46c1e2&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/02/lazarus-hackers-exploited-windows.html  
  
  
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
  
