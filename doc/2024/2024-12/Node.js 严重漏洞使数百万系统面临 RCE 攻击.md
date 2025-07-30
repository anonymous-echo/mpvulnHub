#  Node.js 严重漏洞使数百万系统面临 RCE 攻击   
龙猫  安小圈   2024-12-26 00:45  
  
**安小圈**  
  
  
第576期  
  
**严重漏洞 · RCE攻击【风险预警】**  
  
****  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7v2GzYiatfDGeOcvIoyDY8oC7tWXE1e4YWjTUcSic6pyOiavoc4gZS2xTZXnPDQeibbNsRTGQEXNpbbBw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNicuEUUXm50axXKsUOUbW22YhpbJ93ca7ApkXYEOhxEZxh7co8snkMLqNNTZgK0Bw8THCJJDxO9bg/640?wx_fmt=jpeg "")  
  
在广泛使用的Node.js包“systeminformation”中发现了一个严重的安全漏洞，可能会使数百万个系统面临远程代码执行 （RCE） 攻击。  
  
该漏洞被确定为   
CVE-2024-56334  
，影响该软件包 5.23.6 及以下的版本，该软件包每月下载量超过 800 万次，总下载量达到惊人的 3.3 亿次。  
  
该漏洞源于 getWindowsIEEE8021x 函数中的命令注入缺陷，该函数可检索网络 SSID 信息。  
  
此函数在讲 SSID 作为参数传递给 cmd.exe 之前无法正确清理 SSID。因此，攻击者可以在   
Wi-Fi 网络的 SSID  
 中嵌入恶意命令，然后在调用 getWindowsIEEE8021x 函数是在易受攻击的系统上执行这些命令。  
  
根据程序包的使用方式，此漏洞可能使攻击者能够执行远程代码执行或本地权限提升。该漏洞利用似乎相对简单，只需要本地访问权限即可解近攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7v2GzYiatfDGeOcvIoyDY8oCgvibSRAI3Xw2cicmFGPQwP9lP21QSBfpxjGcicsZHNkcRx1iaej0GOhO0w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
PoC   
演示了  
两种可能的攻击场景：  
  
通过将 SSID 设置为以下方式无限期运行 ping 命令：  
```
a" | ping /t 127.0.0.1 &
```  
  
通过将 SSID 设置为以下方式，以root权限执行具有提升权限的任意可执行文件：  
```
a" | %SystemDrive%\a\a.exe &
```  
  
一旦连接到恶意构建的 Wi-Fi 网络，只需调用易受攻击的函数（例如  
 si.networkInterfaces()   
）即可触发命令的执行。  
  
“systeminformation” 的维护者已在版本 5.23.7 中解决了这个问题。强烈建议此软件包的所有用户立即更新到最新版本。  
  
对于无法升级的开发人员，解决方法包括手动清理传递给特定函数的参数，包括  
si.inetLatency() 、si.inetChecksite()、si.services() 和 si.processLoad()。  
  
此漏洞凸显了 npm 生态系统中持续存在的安全挑战以及与广泛使用的软件包相关的潜在风险。它提醒开发人员：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XUVHsLAnCiafbNPpza417U8rdne5tbVd9KQrpXMgerhxuOdxpe1NTP8ibibYicvsWVonDKMgNJ2GkXkuQ6ajkzBDSw/640?from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
· 定期更新依赖项并监控安全公告  
  
· 实施适当的输入清理，尤其是在处理系统级命令时  
  
· 对项目中使用的第三方软件包进行彻底的安全审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QRNCxNSF1Ek3FfftEd3BO1pdbPC6odcYIbbKlyfHJkUo0scyyzibZIeN8l44S6lAOpHAddQsic1qczYERFrUGCPw/640?from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
  
在“systeminformation”包中发现 CVE-2024-56334 凸显了对软件安全保持警惕的极端重要性，尤其是对于广泛采用的开源库。  
  
随着 Node.js 生态系统的不断发展，开发人员和组织都必须优先考虑安全实践并随时了解可能影响其系统的潜在漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tLV8Gx8km9J2qtZb0RmrJTSUibpbnWUNaZnW7nRmmBic23KZkLCLiajggaRmtCTvK0IM5xyjFtDY8YNCx6dMdWFVQ/640?tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hox1KVQnzGiapffJhGLo1bjRHbxbLYV2cgd54VBV3aEnbiajibjaL4Ya1wz1zNibHzu08s45GibrEaUnQ65dLQawnibA/640?tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
漏洞信息  
  
https://github.com/sebhildebrandt/systeminformation/security/advisories/GHSA-cvv5-9h9w-qp2m  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
**【原文来源： 星尘安全****】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPXIp0CHOLWHoJQicJ7onhDaPpvpCqLkza5ZoKgezBOz9dGV8oAYghuD3z2uNWOey0MmkHaDzpIkTA/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247537603&idx=1&sn=1ccc079f76699e66a63b1983f8b97037&scene=21#wechat_redirect)  
- # 【年末警惕】针对财会人员！“银狐”木马新变种伪装成财税文件在微信群传播！  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247530615&idx=3&sn=58f5cff7d004e5b6669099e7b0931226&chksm=ce222fcff955a6d94d1c86fd0d2677f1d2bdd48c56fe50e0616c14f2567b268e1bad558b945b&scene=21#wechat_redirect)  
- [迪士尼 遭【黑客入侵】| 泄露1.1TB数据，被迫弃用Slack](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247530615&idx=3&sn=58f5cff7d004e5b6669099e7b0931226&chksm=ce222fcff955a6d94d1c86fd0d2677f1d2bdd48c56fe50e0616c14f2567b268e1bad558b945b&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247520585&idx=3&sn=ad5b60917726cceca6868f649edfe0a9&chksm=ce22c6f1f9554fe7637864ef2a3cde10cdfad3015570b03e64c37bdbf0cc75d03a26ffcb2daa&scene=21#wechat_redirect)  
- [【遭入侵】迪士尼，泄露1.2TB内部数据](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247520585&idx=3&sn=ad5b60917726cceca6868f649edfe0a9&chksm=ce22c6f1f9554fe7637864ef2a3cde10cdfad3015570b03e64c37bdbf0cc75d03a26ffcb2daa&token=713211275&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247529598&idx=1&sn=a6a2b5b2fdda54d41ee7af11bd3a443c&chksm=ce2223c6f955aad04a36fb3e52af88d005acbbdc5ffa588c10688245bb113be655f739e34a10&scene=21#wechat_redirect)  
- [惊心动魄！Akira 成功勒索100万美元，全程谈判记录大曝光！](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247529598&idx=1&sn=a6a2b5b2fdda54d41ee7af11bd3a443c&chksm=ce2223c6f955aad04a36fb3e52af88d005acbbdc5ffa588c10688245bb113be655f739e34a10&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247500168&idx=2&sn=59dcc8abe1a52f4672ba739aaaf32e50&chksm=ce229630f9551f26aa12dfce3efcf450d2db4755d1b873dd91c46f4ab67963a13da0954bd43e&scene=21#wechat_redirect)  
- [【技术解析】| 工商银行美国子公司勒索病毒事件分析](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247500168&idx=2&sn=59dcc8abe1a52f4672ba739aaaf32e50&chksm=ce229630f9551f26aa12dfce3efcf450d2db4755d1b873dd91c46f4ab67963a13da0954bd43e&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247499768&idx=1&sn=aa44663417d808f2703b690d7a38c92d&chksm=ce22a840f9552156cf12b9f77a44816ef3781117579292252068052a16cfdc380ab6b167aa8f&scene=21#wechat_redirect)  
  
**【突发】中国工商银行遭勒索软件攻击**  
  
****- [【专题分享】中国工商银行：数据安全技术平台建设实践](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247490269&idx=2&sn=050ba319ad33de8c821f3512689546a3&chksm=ce214d65f956c473a1ec2a777448036bc1a87e30166fc6dd62dea59bab9ac626d94f48101f92&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
