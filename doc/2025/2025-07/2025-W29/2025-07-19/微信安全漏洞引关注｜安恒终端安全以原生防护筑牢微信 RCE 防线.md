> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630794&idx=1&sn=f4129ab9edd27f2f2db8d6ec901dfe84

#  微信安全漏洞引关注｜安恒终端安全以原生防护筑牢微信 RCE 防线  
 安恒信息   2025-07-19 08:21  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/mc7Mmwou4T80KsMmxBtGSfhFMqDlick5aBXnmREbkZ2osGbIJze4yq4iaUTJx9WIh75sW1lQEvuhCibfPJkLf5GZw/640?wx_fmt=jpeg "")  
  
近日，微信 PC 版（3.9 及以下版本）曝出  
高危远程代码执行（RCE）漏洞引发广泛关注。该漏洞可通过目录穿越与远程代码执行组合触发，攻击者利用恶意聊天记录诱导用户点击后，能在用户无感知情况下远程执行任意代码、创建启动项实现持久化等恶意行为，导致系统被控、敏感数据泄露等严重后果，对终端安全构成极大威胁。安恒安全专家面对这一紧急安全风险，启动安全应急分析及验证。经实地验证，安恒终端安全产品凭借原生具备的 “应用防护” 核心能力，能实现对该漏洞攻击链的识别与防护，为用户构筑起坚实的终端安全屏障。  
终端“应用防护”，就是为应对常用的应用软件如office、浏览器、IM这些应用可能被恶意利用而设计的  
针对性主动防御体系。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icVz8RbowK3zF21QkWtLn8A680WgyzD6jQKZC0ibO6nxtr17psoIaZOnMIqicia3U6QZOFibm7WUibQMhuSDvME1g5tw/640?wx_fmt=jpeg "")  
  
  
  
  
  
防护恶意代码执行  
  
  
当微信下载恶意恶意文件及进行运行启动时，应用防护功能通过  
实时行为分析引擎  
，精准识别到异常文件下载及执行行为，第一时间阻断恶意代码的执行，从源头切断攻击路径。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icVz8RbowK3zF21QkWtLn8A680WgyzD6juBMjpup0zuT6aTvhy0fRRAx1QLY2ZU3ShXGPl1JKGREDlibAtP8bdCg/640?wx_fmt=jpeg "")  
  
  
  
阻断恶意持久化  
  
  
针对漏洞利用中常见的 “创建启动项实现持久化” 行为，产品对系统的启动目录、注册表启动项、计划任务等  
关键项  
做实时监控保护，对写入操作进行严格管控，即便攻击者绕过初始拦截尝试创建恶意启动项实现开机自启动，也会被  
即时拦截  
，彻底粉碎其持久化企图。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icVz8RbowK3zF21QkWtLn8A680WgyzD6j1dXvJmumHwu1z5Xzg7Z5G2oR1p2EJNt8cUT3SCuFibcTdxicvTpkrzjw/640?wx_fmt=jpeg "")  
  
  
  
  
关联追踪恶意程序运行  
  
  
  
除了对微信的直接操作行为进行恶意识别防护，应用防护功能还会对通过  
微信下载的程序  
进行关联追踪，之后就算不是通过微信直接启动，也能进行威胁防护。即就算黑客先仅通过微信进行恶意程序下载，然后再通过其他程序进行启动或诱导用户手工进行启动，其运行行为都会被实时监控，在其造成实际危害前完成拦截，实现  
 “一次追踪，全程防护”  
。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icVz8RbowK3zF21QkWtLn8A680WgyzD6jTrZPzaRluLSFkJcib7I7hIFVCcH7axSyiagiba64yMsIRIQFmzKvVKUgw/640?wx_fmt=jpeg "")  
  
  
需特别说明的是，上述针对微信 RCE 漏洞的防护能力，均源自安恒终端安全产品原生的 “应用防护” 体系，无需依赖紧急规则升级或临时补丁。这意味着在  
漏洞曝出前  
，产品已凭借成熟的防护架构，为用户提供了前瞻性安全保障；  
漏洞曝出后  
，用户无需额外操作，即可依托既有能力有效抵御攻击。在此，安恒信息也  
提醒  
广大用户：请尽快将微信 PC 版升级至  
最新版本  
，从软件本身修复漏洞；同时，依托  
安恒终端安全产品  
的 “应用防护” 能力，构建 “主动防御 + 漏洞修复” 的  
双重  
安全防线，全方位抵御各类终端威胁，守护业务与数据安全。  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icVz8RbowK3yicL1W21LaIIKlNibL1zDMVhKzAndiclzHbKI4tbvBCMadUVPibOhXn47EceD0rdLaR0cKibPmhVxxBcg/640?wx_fmt=png "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/icVz8RbowK3yEfgqaJ4nxoES6ggmVq7icUa5WvlGfMttCbpAPMkSMR3BZXmYLJRhVoxSoxhiaXPticcr2PiaibWAScOQ/640?wx_fmt=gif "")  
  
  
将**“安恒信息”**  
微信公众号**设为星标**  
  
关注信息不走丢哦！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/icVz8RbowK3wRq3BqNDZacia5FAgbviceFx6aPdHmYo1VtHkTbOlbxJb8N28vYU2Dkl2ecQm7CukLwJhe3drbloibA/640?wx_fmt=gif "")  
  
  
**往期**  
**精彩****回顾**  
  
  
[权威机构发布中国安全智能体市场报告：安恒信息六大类全面覆盖](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630571&idx=1&sn=5df3ce9d4cd23fbfef162f70c2a4adc0&scene=21#wechat_redirect)  
  
  
2025-07-11  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630571&idx=1&sn=5df3ce9d4cd23fbfef162f70c2a4adc0&scene=21#wechat_redirect)  
  
  
[解读丨《关键信息基础设施商用密码使用管理规定》发布，且看安恒信息关基商密应用](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630531&idx=1&sn=a0b8b463b8c9e5aaf1b64d2ea1af2821&scene=21#wechat_redirect)  
  
  
2025-07-10  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630531&idx=1&sn=a0b8b463b8c9e5aaf1b64d2ea1af2821&scene=21#wechat_redirect)  
  
  
[权威报告发布｜安恒信息WAF市场份额位居国内第三](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630186&idx=1&sn=a06a653bce9229a4f0e03af5b49506cf&scene=21#wechat_redirect)  
  
  
2025-07-08  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NTE0MjQyMg==&mid=2650630186&idx=1&sn=a06a653bce9229a4f0e03af5b49506cf&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/icVz8RbowK3wcAnwz5Wia43nYlGWM5teehpXAibr36rRQhBf1zl5yTiaNJGQgxsTnicyicHfeQ9hN3j2FYPCCNYoNXFg/640?wx_fmt=gif "")  
  
  
  
  
  
