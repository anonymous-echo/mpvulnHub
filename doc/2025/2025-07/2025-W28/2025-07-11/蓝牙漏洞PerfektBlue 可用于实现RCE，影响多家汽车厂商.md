> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523555&idx=1&sn=caf9ee84b43c4fc81ee51bfbe2c7d11d

#  蓝牙漏洞PerfektBlue 可用于实现RCE，影响多家汽车厂商  
Bill Toulas  代码卫士   2025-07-11 10:37  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**影响OpenSynery 公司生产的 BlueSDK Bluetooth 栈的四个严重漏洞被统称为 “PerfektBlue”，可被用于实现远程代码执行并可能用于访问多家汽车厂商如奔驰、大众和斯柯达所生产汽车的关键元素。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRibSOf2oefmWuft2DriawV8ic11jXPybxL40XUtBdk0dGDibBK91vDyj2lfFgwRpHXvcLpahgCyMdhzg/640?wx_fmt=png&from=appmsg "")  
  
  
OpenSynergy 公司在去年六月证实了这些漏洞的存在并在2024年9月发布补丁，但很多汽车厂商尚未推送正确的固件更新。至少有一家主要的原始设备制造商（OEM) 在最近才获悉这些安全风险。  
  
这些漏洞可组合用于一个被研究员称为 “PerfektBlue 攻击”的利用链中，且可被攻击者无线传播，“至多要求用户点击一次”。尽管 OpenSynergy 公司生产的 BlueSDK广泛用于汽车行业，不过它也用于其它行业中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRibSOf2oefmWuft2DriawV8icWXG9QbSFeXGsice780Wicek8fPYbnApGotqQ6vRiczib95WSAC0pWenfKw/640?wx_fmt=png&from=appmsg "")  
  
**PerfektBlue 攻击**  
  
  
  
专注于汽车安全领域的公司 PCA Cyber Security的渗透测试团队发现了 PerfektBlue 漏洞并在2024年5月报送给 OpenSynergy 公司。他们是Pwn2Own 汽车大赛的常客，自去年开始已在汽车系统中发现了50多个漏洞。他们表示，PerfektBlue 攻击影响“汽车和其它行业中的数百万台设备”。  
  
由于研究员无法访问源代码，因此它们分析了BlueSDK的编译二进制，并从中发现了多个漏洞。这些漏洞严重程度从低危到高危不等，可用于通过车载信息娱乐系统访问汽车内部机制：  
  
- CVE-2024-45434（高危）：位于Bluetooth 配置AVRCP 服务中的释放后使用漏洞，可导致媒体设备遭远程控制。  
  
- CVE-2024-45431（低危）：对逻辑链路控制与适配协议 (L2CAP) 通道的远程通道标识符 (CID) 的验证不当。  
  
- CVE-2024-45433（中危）：无线电频率通讯 (RFCOMM) 协议中的不正确函数终止漏洞。  
  
- CVE-2024-45432（中危）：RFCOMM协议中函数调用的参数不正确。  
  
  
  
研究人员虽然并未分享利用 PerfektBlue 漏洞的完整技术详情，但表示与受影响设备配对的攻击者能够利用这些漏洞“操纵系统、提升权限，并横向移动到目标产品的其它组件中 ”。  
  
PCA Cyber Security 在大众 ID.4（ICAS3 系统）、奔驰（NTG6）和斯柯达速派 (MTB3)的信息娱乐头单元上展示了 PerfektBlue 攻击，并在TCP/IP上获得了一个逆向 shell，可允许网络上的设备如汽车中的组件之间进行通信。  
  
研究人员表示，通过在车载信息娱乐系统 (IVI) 上实现RCE，黑客能够追踪GPS坐标、窃听车内谈话、访问手机联系人并可能横向移动到汽车更为重要的子系统中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRibSOf2oefmWuft2DriawV8icWXG9QbSFeXGsice780Wicek8fPYbnApGotqQ6vRiczib95WSAC0pWenfKw/640?wx_fmt=png&from=appmsg "")  
  
**风险和暴露**  
  
  
  
OpenSynergy 的 BlueSDK 虽然广泛用于汽车行业，但由于自定义和重装流程以及汽车嵌入式软件组件缺乏透明度的原因，难以判断依赖于它的厂商具体有哪些。  
  
PerfektBlue 主要是一次点击RCE漏洞，因为多数情况下，需要诱骗用户允许与攻击者设备配对。然而，一些汽车厂商将信息娱乐系统配置为无需任何确认即可配对。  
  
PCA Cyber Security 公司的研究人员表示，已通知大众、奔驰和斯柯达相关漏洞信息，并给与他们足够的时间应用补丁，但却并未从这些厂商收到漏洞已修复的反馈。  
  
当被询问道是否已经推送 OpenSynergy 公司发布的修复方案时，并未联系到奔驰的发言人，大众表示他们在了解到漏洞后，就开始着手调查这些风险的影响和修复方法。大众的一名发言人表示，“调查显示，在某些条件下，很有可能在无需授权的情况下，通过蓝牙连接到汽车的信息娱乐系统。”  
  
大众表示，只要在同时满足多个条件的情况下才可能利用这些漏洞：  
  
- 攻击者位于汽车附近的最大距离是5到7米；  
  
- 汽车的点火系统必须是开启状态。  
  
- 信息娱乐系统必须处于配对状态，即汽车用户必须主动配对蓝牙设备；  
  
- 汽车用户必须主动允许屏幕上攻击者的外部蓝牙访问权限。  
  
  
  
大众的一名发言人表示，即使满足了这些条件，攻击者连接到了蓝牙界面，“他们必须处于与汽车最大距离为5到7米的范围内”。大众强调称，在成功利用情况下，攻击者无法干扰关键的汽车功能如转动方向盘、驾驶员协助、引擎或刹车，因为这些功能“位于一个不同的控制面板上，该面板通过自身的安全功能低于外部扰乱。”  
  
研究人员表示，他们上个月在汽车行业的第四家原始设备制造商设备上证明了 PerfektBlue 攻击，不过OpenSynergy 公司并未告知相关公司。研究人员表示，“我们决定不披露这家OEM的名称，因为他们没有足够的时间进行应对。我们计划在2025年11月举办的一场会议上披露该OEM以及PerfektBlue 的完整技术详情。”  
  
目前尚不清楚 PerfektBlue 对OpenSynergy 客户的影响范围和规模有多大。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[第三方依赖关系的风险：利用数十个易受攻击的 NuGet包瞄准 .NET 平台](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506255&idx=1&sn=5dff2ef15506b4ba509e43afdb2a22d8&scene=21#wechat_redirect)  
  
  
[或因第三方数据遭泄露，诺基亚源代码被盗](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521416&idx=2&sn=af708336e0629a268e35f7a6fb2a263b&scene=21#wechat_redirect)  
  
  
[Splunk 修复企业产品中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519961&idx=2&sn=8bd333df15de255db874f15d0653517b&scene=21#wechat_redirect)  
  
  
[Splunk 修复 Enterprise 和 IT Service Intelligence 中的多个高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517521&idx=1&sn=4ba48f444fa6833ef1644afc64166e6d&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/splunk-third-party-packages-soar-versions/  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
