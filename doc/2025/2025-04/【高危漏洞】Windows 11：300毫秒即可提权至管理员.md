#  【高危漏洞】Windows 11：300毫秒即可提权至管理员   
 安小圈   2025-04-18 00:45  
  
**安小圈**  
  
  
第648期  
  
**Windows11 · 高危漏洞**  
  
****  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbNqM3Lnaqq6icl1RhgBIMsJlcNVrkQbxYgNHeUIx8rSdia6liauYeiag35VjlRo1j4QmZ7xyHWiak6KqJA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbOVztHhrSawy3u5KqPTRs9pPtTicoFgjxhUlRWLrIutmy4fLCCGrCvfKahO7nc6kcIy7ibbxic3Jgpmg/640?wx_fmt=png "")  
  
Windows 11 存在一个严重漏洞，攻击者可在短短 300 毫秒内从低权限用户提升至系统管理员权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbNUlJYnNFrdxSl0V8htqZZWaZGyTDyPtp4ibKslTnnKcRpEuRGntPI2VIkAVrjcRUb0dKPxjicmu3SA/640?wx_fmt=png "")  
  
  
该漏洞编号为 CVE-2025-24076，通过精密的 DLL 劫持技术利用 Windows 11“移动设备”功能的缺陷。安全研究人员于 2024 年 9 月发现此漏洞，并于 2025 年 4 月 15 日公开披露，其攻击目标是 Windows 11 摄像头功能加载的 DLL 文件。  
  
研究人员发现，位于用户可修改目录 %PROGRAMDATA%\CrossDevice\ 下的 CrossDevice.Streaming.Source.dll 文件会先由普通用户进程加载，随后被高权限系统进程加载。  
  
Compass Security 公司的 John Ostrowski 表示：“这个漏洞是典型的 DLL 劫持场景，但包含极具挑战性的时间控制因素，攻击窗口期极短——仅有 300 毫秒，但我们开发了可靠的技术手段实现稳定利用。”  
  
**01**  
  
  
  
**Windows 11 权限提升漏洞技术细节**  
  
漏洞利用过程面临多项技术挑战。研究人员最初使用 PrivescCheck 工具进行自动化扫描，发现非特权用户对 COM 服务器模块文件具有修改权限：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwgsgjIdGeMY4c8DI0eClFGaXaT2viczJGjLCt0H3ricuuBwSYvtgq1ewA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
为克服短暂的时间窗口，研究人员采用机会锁（Opportunistic Locks）技术在关键时刻暂停程序执行。通过微软 Detours 库，他们拦截了专门针对 GetFileVersionInfoExW 的 Windows API 调用，以确定可靠替换文件的时机。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwsiazNT5OFiaHs696412dnNgxltvSicYGB8I3jOu4vQTCYHW4YW3825eMw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
研究人员创建了恶意 DLL 文件，该文件在保留原有功能的同时添加了未授权命令：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwjWaw8qQaJqADOgTdxaiczt0Zeje6A1xcbMS6Z3tmhf2UOvVEAz4JT2A/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
当高权限进程加载该 DLL 时，恶意代码将以 SYSTEM 权限执行。为确保被替换的 DLL 保持原有功能，研究人员实现了代理机制，将函数调用转发至原始 DLL：  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38icATbzGX97j2YbGeTvf8RwzRcUvugGwuY5hYqgXB8bWk0knBkN1yg8gJC0mib9TvhO2uHV9Jg0ZOA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**02**  
  
  
  
**漏洞缓解措施**  
  
该漏洞影响启用了“移动设备”功能的 Windows 11 系统，该功能允许用户将手机链接为网络摄像头使用。微软已在 2025 年 3 月的安全更新中发布补丁。  
  
此发现凸显了在特权进程中实施严格文件访问控制和签名验证的重要性。即使在没有可用补丁的情况下，端点检测与响应（EDR）解决方案也能通过行为监控检测此类攻击。  
  
研究人员建议 ：“虽然保持系统更新至关重要，但用户还可采取额外防护措施，使用 EDR 解决方案可以主动检测异常行为，识别可疑活动。”  
  
微软将主系统级权限提升漏洞编号为 CVE-2025-24076，同一功能中的相关用户间攻击向量编号为 CVE-2025-24994。强烈建议用户安装最新的 Windows 安全更新以修复这些漏洞。  
  
该漏洞利用案例表明，即使是现代操作系统，在新功能实现中也可能受到长期存在的攻击技术威胁，特别是当熟练的攻击者利用时间差和竞争条件时。  
  
  
  
  
END  
  
  
  
****  
****  
**【内容**  
**来源：FreeBuf】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247536892&idx=1&sn=fae617872d88e82db85a951a211ec591&scene=21#wechat_redirect)  
- **2025年 · 网络威胁趋势【预测】**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247535616&idx=2&sn=d1e03bea4d88b79cda82f1f4a15afcc0&scene=21#wechat_redirect)  
- **【实操】常见的安全事件及应急响应处**  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247532239&idx=3&sn=ed53d89db2437bae8ef2e9b1c4063b73&chksm=ce222977f955a0614b00b6616f3e92f93ec9df078127eabcf4f7a281496ff6a36b2ebc7a2765&scene=21#wechat_redirect)  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
