#  Windows 11曝权限提升漏洞，攻击者300毫秒内可获取管理员权限   
 邑安全   2025-04-16 08:45  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqlnSibE1hpQIEcCPLeeFmSKHAWKwxjfiarNKI7ULqnhHwU9SHNpWYC8pA/640?wx_fmt=png&from=appmsg "")  
  
Windows 11 中的一个严重漏洞允许攻击者在短短 300 毫秒内从低权限用户升级到完全系统管理员权限。  
  
该漏洞被跟踪为 CVE-2025-24076，通过复杂的 DLL 劫持技术利用了 Windows 11“移动设备”功能的弱点。  
  
该安全漏洞于 2024 年 9 月发现并于 2025 年 4 月 15 日公开披露，针对 Windows 11 的相机功能加载的 DLL 文件。  
  
研究人员发现，位于用户可修改的 %PROGRAMDATA%\CrossDevice\ 目录中的文件CrossDevice.Streaming.Source.dll首先由常规用户进程加载，然后由高权限系统进程加载。  
  
“这个漏洞代表了一个经典的 DLL 劫持场景，具有具有挑战性的计时元素，”Compass Security 的 John Ostrowski 对 Cyber Security News 说。“机会之窗非常小，只有 300 毫秒，但我们开发了使漏洞利用可靠的技术。”  
  
Windows 11 权限提升漏洞  
  
该漏洞利用涉及多项技术挑战。使用 PrivescCheck 工具进行的初步自动扫描显示，非特权用户对 COM 服务器模块文件具有修改权限：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqULDjkOM6wm7RSO6d8RHVelibI2KDJUuUr5GRQmsEJrhNrzvc0dZzTug/640?wx_fmt=png&from=appmsg "")  
  
为了克服狭窄的时间窗口，研究人员采用了机会锁在需要的精确时刻停止程序执行。  
  
使用 Microsoft 的 Detours 库，他们拦截了专门针对 GetFileVersionInfoExW 的 Windows API 调用，以确定何时可以可靠地替换文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqGqK3Wge9fkCqngCOX5Ga9H4QEyyvmqu6fy1Wf4bKcHTn9iapR4SulIw/640?wx_fmt=png&from=appmsg "")  
  
研究人员创建了一个恶意 DLL，它在添加未经授权的命令时保持预期的功能：  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqXHm26iaSfeiahdKX1t0eoKRic194ZaT5wiaxFHFf96BfrKiaPIAG3FrQZ2g/640?wx_fmt=png&from=appmsg "")  
  
此代码在由高权限进程加载时以 SYSTEM 权限执行。为了确保被替换的 DLL 保持功能，研究人员实现了一个代理，该代理将函数调用转发到原始 DLL：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8sdyR6ic0M2acDAVJDe45WPqlfeiawiax8hKcLRhbRoj9pkMSxprqmh7vxMpTwI3fWwdOSkpy1Sf4icjQ/640?wx_fmt=png&from=appmsg "")  
  
缓解措施  
  
该漏洞影响了具有“移动设备”功能的 Windows 11 系统，该功能允许用户链接他们的手机以将手机的摄像头用作网络摄像头。Microsoft 在其 2025 年 3 月的安全更新中发布了一个补丁。  
  
这一发现凸显了在特权进程中严格的文件访问控制和签名验证的重要性。  
  
端点检测和响应 （EDR） 解决方案可以通过行为监控来检测此类攻击，甚至可以在可用补丁之前检测到。  
  
“虽然使您的系统保持最新状态至关重要，但您可以采取其他措施来保护您的机器，”研究人员说。“通过使用 EDR 解决方案，您可以主动检测异常行为并识别异常活动。”  
  
Microsoft 已将 CVE-2025-24076 分配给主要系统级权限提升，并将 CVE-2025-24994 分配给同一功能中的相关用户到用户攻击媒介。  
  
强烈建议用户应用最新的 Windows 安全更新来缓解这些漏洞。  
  
该漏洞利用表明，当在新功能中实施时，即使是现代作系统也容易受到长期存在的攻击技术的攻击，尤其是当熟练的攻击者利用计时和争用条件时。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/windows-11-vulnerability-gain-admin-access/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
