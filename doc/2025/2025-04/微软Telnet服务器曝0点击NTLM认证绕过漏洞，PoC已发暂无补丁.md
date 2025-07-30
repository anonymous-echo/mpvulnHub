#  微软Telnet服务器曝0点击NTLM认证绕过漏洞，PoC已发暂无补丁   
 安小圈   2025-04-30 00:46  
  
**安小圈**  
  
  
第657期  
  
**微软 漏洞· 远程攻击**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPoumFVAlibWia2XOdm5v7bGBSK9icsz9vgjEw8IxZhbmrL469Jic7U0L6bQjRwuBJWtGV0akKSvaWsdA/640?wx_fmt=jpeg "")  
  
![](http://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOicgoB4iaTMSrN8wJWQ6zA8wp7eayt7VT0AYyCP4QZp5TvoaxVyKRXvUzLc4MRAon231C3egjn9ZpQ/640?wx_fmt=jpeg "")  
  
网络安全研究人员发现微软Telnet服务器存在严重漏洞，远程攻击者无需有效凭证即可完全绕过认证机制，获取管理员权限。根据Hacker Fantastic发布的报告，该漏洞涉及微软Telnet认证协议(MS-TNAP)，对传统Windows系统构成重大安全威胁，且目前尚无官方补丁。  
  
报告指出："微软Telnet服务器中存在一个关键的0点击远程认证绕过漏洞，攻击者无需有效凭证即可获得包括管理员在内的任意用户访问权限"。该漏洞源于Telnet服务器处理NTLM（NT LAN Manager）认证流程时的配置错误。  
  
  
**01**  
  
  
  
**受影响系统范围**  
  
该漏洞影响以下广泛使用的微软操作系统版本：  
- Windows 2000  
  
- Windows XP  
  
- Windows Server 2003  
  
- Windows Vista  
  
- Windows Server 2008  
  
- Windows 7  
  
- Windows Server 2008 R2  
  
**02**  
  
  
  
**漏洞技术原理**  
  
漏洞成因在于Telnet服务器错误地初始化NTLM认证凭据并错误处理双向认证。具体表现为服务器在认证握手阶段设置了存在缺陷的SSPI（安全支持提供程序接口）标志：  
  
报告解释称："服务器使用SECPKG_CRED_BOTH标志初始化NTLM安全机制"，并且"调用AcceptSecurityContext()函数时启用了ASC_REQ_DELEGATE和ASC_REQ_MUTUAL_AUTH标志"。  
  
这种错误配置导致认证关系出现危险逆转——服务器反而向客户端证明自身身份，而非验证客户端身份。  
  
  
**03**  
  
  
  
**漏洞利用过程**  
  
Hacker Fantastic发布的概念验证(PoC)利用程序通过以下步骤实施攻击：  
1. 使用特定标志请求双向认证  
  
1. 为目标管理员账户使用NULL空密码  
  
1. 操纵SSPI标志触发服务器认证逻辑缺陷  
  
1. 发送经过篡改的NTLM Type 3类型消息欺骗服务器  
  
1. 最终完全绕过认证，开启具有管理员权限的Telnet会话  
  
报告强调："攻击者可通过发送双向认证数据包并利用SSPI配置绕过服务端认证，从而获取主机上任意账户的访问权限"  
  
  
已发布的PoC工具**telnetbypass.exe**针对本地主机或域内主机，要求目标系统Telnet Server服务处于运行状态。  
  
  
**04**  
  
  
  
**缓解措施建议**  
  
令人担忧的是，"目前该漏洞尚无补丁"。建议相关组织立即采取以下防护措施：  
- **禁用所有系统上的Telnet Server服务**  
  
- **采用SSH等更安全的远程管理方案替代Telnet**  
  
- **实施网络层过滤，**  
仅允许可信IP和网络访问Telnet服务  
  
- **应用控制策略**  
阻止未经授权的Telnet客户端连接  
  
值得注意的是，为降低大规模利用风险，"该漏洞利用的源代码暂未公开"，目前仅向公众发布了二进制格式的PoC程序。  
  
  
  
  
END  
  
  
  
**【 内容**  
**来源：FreeBuf】**  
  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
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
  
