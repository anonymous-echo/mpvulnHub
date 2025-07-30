> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547132&idx=1&sn=cd484270f0cd9ed5dc17fdeafb2e76dd

#  微软紧急修复高危蠕虫级RCE漏洞，威胁全网Windows系统  
FreeBuf  安小圈   2025-07-10 12:00  
  
**安小圈**  
  
  
第705期  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNPJGX2FmlEQ3g3kjplJRZ8v3pDCJpfrXGWENt1IMtM06tCD4CprN8vfNliavtia7IhTKakxWh12O0w/640?wx_fmt=jpeg "")  
# 微软已发布关键安全更新，修复编号为CVE-2025-47981的高危漏洞。该漏洞存在于SPNEGO扩展协商(NEGOEX)安全机制中，属于基于堆的缓冲区溢出漏洞，影响多个Windows和Windows Server版本。  
# 该漏洞CVSS评分为9.8分(满分10分)，属于最高危级别，可在无需用户交互的情况下实现远程代码执行。  
#   
  
**Part01**  
  
## 核心要点  
#   
# 1. Windows SPNEGO中存在基于堆的缓冲区溢出漏洞，CVSS评分9.8/10，可实现远程代码执行  
# 2. 攻击者无需用户交互或特权，仅需向服务器发送恶意消息即可执行代码  
# 3. 影响Windows 10(1607及以上)、Windows 11及Windows Server等33种系统配置  
# 4. 微软于2025年7月8日发布更新，建议优先部署在面向互联网的系统及域控制器上  
# 该漏洞允许未经授权的攻击者通过网络连接执行任意代码，对企业环境构成严重威胁。  
#   
  
**Part02**  
  
## 可蠕虫传播的RCE漏洞  
#   
# 该漏洞存在于Windows SPNEGO扩展协商机制中，该机制是对简单且受保护的GSS-API协商机制的扩展。  
# CVE-2025-47981被归类为CWE-122，属于可远程利用的基于堆的缓冲区溢出漏洞。其CVSS向量字符串CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C表明，该漏洞可通过网络发起攻击，复杂度低，无需特权或用户交互，但对机密性、完整性和可用性影响极大。  
# 安全研究人员评估该漏洞"极有可能被利用"，不过截至披露时尚未发现公开利用代码或实际攻击案例。该漏洞尤其影响运行Windows 10版本1607及更高版本的客户端计算机，这些系统默认启用了组策略对象"网络安全：允许PKU2U身份验证请求使用在线身份"。  
# 攻击者可通过向受影响服务器发送恶意消息来利用CVE-2025-47981，可能获得远程代码执行能力。基于堆的缓冲区溢出发生在NEGOEX处理机制中，允许攻击者覆盖内存结构并控制程序执行流程。这种可蠕虫传播的特性意味着漏洞可能通过网络连接的系统自动传播，无需用户干预。  
# 该漏洞由安全研究人员通过协调披露机制发现，包括匿名贡献者和Yuki Chen。微软对这些研究人员的致谢体现了负责任漏洞披露对维护企业安全态势的重要性。  
#   
  
**Part03**  
  
## 风险因素  
#   
#   
#   
  
**Part04**  
  
## 补丁部署  
#   
  
微软于2025年7月8日发布了全面的安全更新，针对不同Windows配置修复了该漏洞。关键更新包括Windows Server 2025(版本10.0.26100.4652)、Windows 11 24H2版(版本10.0.26100.4652)、Windows Server 2022 23H2版(版本10.0.25398.1732)以及Windows Server 2008 R2(版本6.1.7601.27820)等旧系统的补丁。  
  
  
企业应优先为面向互联网的系统和域控制器部署这些安全更新。补丁可通过Windows Update、Microsoft更新目录和Windows Server更新服务(WSUS)获取。系统管理员应通过核对微软安全公告中的版本号来验证补丁是否成功安装，并考虑在部署补丁期间实施网络分段作为额外防御措施。  
  
  
**参考来源：**  
  
Microsoft Patches Wormable RCE Vulnerability in Windows and Windows Server  
  
https://cybersecuritynews.com/microsoft-patches-wormable-rce-vulnerability/  
  
END  
  
  
  
**【以上内容**  
**来源于：FreeBuf】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
- [【HVV】护网系列 威胁情报共享7.9](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547108&idx=1&sn=01f68c9cc76760e8e5e0615df3b54c6c&scene=21#wechat_redirect)  
  
  
- [25HVVRT钓鱼样本，警惕！多家单位已中...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547104&idx=1&sn=8e06fcde039b325eedcb2eac8ba04f95&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.8](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547054&idx=1&sn=014e2f4baedfea584d880c612e51b884&scene=21#wechat_redirect)  
  
  
- [【更！】25HVV热点攻击漏洞含0day，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547053&idx=1&sn=ab425df27b630dfa1c1d59759bf1ad37&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.7](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547048&idx=1&sn=d943617032f197fb6cb70fff9f8eb3d2&scene=21#wechat_redirect)  
  
  
- [25HVV最新0day更新，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546998&idx=1&sn=c3077c2a50dfec80de8f9e21b507ae53&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
- [【HW】8个因护网被开除的网安人](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
- [HW应急溯源：50个高级命令实战指南](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
  
  
- [震惊全球！中国团队攻破RSA加密！RSA加密告急？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546856&idx=1&sn=11b36f6fabde860e889e4ac2f4797bba&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOugegrykhydnkHibcSWjpibTBZoK6jjGxJiax1BcwwctpA5SBric9aPdQFXsxFnn4LQJWdkYwbtPN0gg/640?wx_fmt=jpeg "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
- [2025年【护网】攻防演练时间已定！](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
[突发！小红书惊现后门......](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2C0ibcMl4Tea8hM59iaZoR1FDMTCUswDiclc1icLoSywpkWbdqyb6uBNcnA/640?wx_fmt=jpeg "")  
- [2025年“净网”“护网”专项工作部署会在京召开，看看都说了哪些与你我相关的关键内容？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546673&idx=1&sn=53fe0365785465d4ff6193a9ca639119&scene=21#wechat_redirect)  
  
  
- # 护网即将来临，这场网安盛会带给了我们打工人什么......  
  
- [护网在即，企业还有什么新思路可以应对吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546698&idx=1&sn=55ab4ac8dffb5f7ccf02a4f759537acf&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2Noz3ibYqNZ52uicBtuVVlFRg6vSuF8YFjPvCVma1ADrT1ViaKVE9URNOA/640?wx_fmt=jpeg "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
- [网安同行们，你们焦虑了吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546466&idx=1&sn=a9d55d0b430dbf61dc219fd71ce25ae1&scene=21#wechat_redirect)  
- # 网安公司最后那点体面，还剩下多少？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
