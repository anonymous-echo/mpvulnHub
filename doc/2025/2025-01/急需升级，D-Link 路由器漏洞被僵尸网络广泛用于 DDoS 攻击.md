#  急需升级，D-Link 路由器漏洞被僵尸网络广泛用于 DDoS 攻击   
龙猫  安小圈   2025-01-03 00:45  
  
****  
**安小圈**  
  
  
第581期  
  
**快升级 · D-Link路由器**  
  
****  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/jDxr6RVaB7uMUZsmHvlRS4lPKuiaFhr7T2qJAJiavGZDsg68iauiaK3M09dKgCX0WdDBGH0HH7Ucf1fDt6PiaGGJjLw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNXxiaYciaox8icl4sxDzicNReRq4sMO9hJTibSOMJicicdEDYxKpjCUrnjPibm13ve2Tz9LibeVwcHLofQiaaw/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XUVHsLAnCiafbNPpza417U8rdne5tbVd9KQrpXMgerhxuOdxpe1NTP8ibibYicvsWVonDKMgNJ2GkXkuQ6ajkzBDSw/640?from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
**僵尸网络活动增加**  
  
：新的“FICORA”和“CAPSAICIN”僵尸网络（Mirai 和 Kaiten 的变体）的活动激增。  
  
**被利用的漏洞**  
  
：攻击者利用已知的 D-Link 路由器漏洞（例如 CVE-2015-2051、CVE-2024-33112）来执行恶意命令。  
  
**僵尸网络功能**  
  
：两种僵尸网络都使用 shell 脚本，以 Linux 系统为目标，杀死恶意软件进程，并进行 DDoS 攻击。  
  
**全球影响**  
  
：FICORA 针对多个国家，而 CAPSAICIN 专注于东亚，东亚的活动持续了两天多。  
  
**缓解措施**  
  
：建议定期更新固件和强大的网络监控，以防止漏洞利用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QRNCxNSF1Ek3FfftEd3BO1pdbPC6odcYIbbKlyfHJkUo0scyyzibZIeN8l44S6lAOpHAddQsic1qczYERFrUGCPw/640?from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other "")  
  
  
FortiGuard Labs 观察到，“FICORA”和“CAPSAICIN”这两个僵尸网络在 2024 年 10 月和 11 月的活动激增。FortiGuard Labs 的威胁研究团队在其与 Hackread.com 独家分享的博客文章中解释说，这些僵尸网络是著名的 Mirai 和 Kaiten 僵尸网络的变体，可以执行恶意命令。  
  
进一步的调查显示，这些僵尸网络的分发涉及利用 D-Link 漏洞，这些漏洞允许远程攻击者通过家庭网络管理协议 （HNAP） 接口上的 GetDeviceSettings 操作执行恶意命令。  
  
这些漏洞包括 CVE-2015-2051、CVE-2019-10891、CVE-2022-37056 和 CVE-2024-33112。这些 CVE 代表攻击者利用的 D-Link 路由器中的特定漏洞实例。它们通常涉及 HNAP 处理用户输入和身份验证方式的缺陷。攻击者使用 HNAP 接口来传播恶意软件，而这一弱点在近十年前首次暴露出来。  
  
受影响的平台包括 D-Link DIR-645 有线/无线路由器 Rev. Ax、D-Link DIR-806 设备以及 D-Link GO-RT-AC750 GORTAC750_revA_v101b03 和 GO-RT-AC750_revB_FWv200b02。根据 FortiGuard Labs IPS 遥测数据，该僵尸网络具有很高的威胁级别，并通过较旧的攻击方式进行传播。  
  
FICORA 僵尸网络是一种恶意软件，它以多种 Linux 架构为目标，并使用 ChaCha20 加密算法对其配置进行加密。此外，它的功能还包括暴力破解，嵌入带有十六进制 ASCII 字符的 shell 脚本以识别和杀死其他恶意软件进程，以及使用 UDP、TCP 和 DNS 等协议的 DDoS 攻击功能。  
  
根据 FortiGuard Labs 威胁研究团队的博客文章，这个僵尸网络会下载一个名为“multi”的 shell 脚本，该脚本使用包括 wget、ftpget、curl 和 tftp 在内的各种方法来下载实际的恶意软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/jDxr6RVaB7uMUZsmHvlRS4lPKuiaFhr7Te6QWBXKCPIQp4JicduDLrzpaia4hGe91OVFpA203ZbTIAA2Mpk7WJUMQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
使用 “curl” 命令的下载器脚本 “multi”   
  
FICORA 僵尸网络攻击针对全球许多国家，由来自荷兰的攻击者触发。但与 FICORA 不同的是，CAPSAICIN 攻击仅在 2024 年 10 月 21 日至 22 日的两天内非常活跃，并以东亚国家为目标。  
  
然而，与 FICORA 一样，它也展示了多种功能，包括下载名为“bins.sh”的 shell 脚本、针对多个 Linux 架构、杀死已知的僵尸网络进程、与其 C2 服务器建立连接、发送受害者主机信息以及提供 DDoS 攻击功能。  
  
尽管这种攻击中利用的漏洞已经为人所知近十年，但这些攻击仍然普遍存在，这令人担忧。尽管如此，为了降低 D-Link 设备被僵尸网络入侵的风险，建议定期更新固件并保持全面的网络监控。  
  
****  
END  
  
  
  
**【原文来源：****星尘安全】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMjDKCY2Lk2HcctzBYfqOcjU4Djy5iamYYkH1KlHltmMmibhVdKb0UKiaWm6EYfY9aRLtffwzUCl7FCg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247538213&idx=3&sn=7eaac973e7e174309c5f01b47d5a5df0&scene=21#wechat_redirect)  
- [大众汽车集团欧洲发生严重数据泄漏，80万车主可被定位](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247538213&idx=3&sn=7eaac973e7e174309c5f01b47d5a5df0&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247536892&idx=1&sn=fae617872d88e82db85a951a211ec591&scene=21#wechat_redirect)  
- [2025年 · 网络威胁趋势【预测】](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247536892&idx=1&sn=fae617872d88e82db85a951a211ec591&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247535616&idx=2&sn=d1e03bea4d88b79cda82f1f4a15afcc0&scene=21#wechat_redirect)  
- [【实操】常见的安全事件及应急响应处](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247535616&idx=2&sn=d1e03bea4d88b79cda82f1f4a15afcc0&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247533863&idx=1&sn=4e22237a8e82970dace044e3ecd96e5d&chksm=ce22129ff9559b8900b7552e33ca9756418ea0ab860f403e5d6ab3db42e8e142d341de4726ec&scene=21#wechat_redirect)  
- # 网络安全等级保护备案实施细则（试行）  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247532239&idx=3&sn=ed53d89db2437bae8ef2e9b1c4063b73&chksm=ce222977f955a0614b00b6616f3e92f93ec9df078127eabcf4f7a281496ff6a36b2ebc7a2765&scene=21#wechat_redirect)  
- [2024 网络安全人才实战能力白皮书安全测试评估篇](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247532239&idx=3&sn=ed53d89db2437bae8ef2e9b1c4063b73&chksm=ce222977f955a0614b00b6616f3e92f93ec9df078127eabcf4f7a281496ff6a36b2ebc7a2765&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247532953&idx=1&sn=26940e24e03924e0175674f735932582&chksm=ce221621f9559f376250e05de03e659387da1e8283a1937e2b068e45967d6eb944fe17950737&scene=21#wechat_redirect)  
- # 【惊！】疑似某 网络安全公司的防火墙访问权限在泄露论坛出售  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247531648&idx=2&sn=521bca396c0738f277b781ef105a7c43&chksm=ce222b38f955a22e856189a8ed0aee2e54a669502a86424b8d9733d86147075764543a358325&scene=21#wechat_redirect)  
- [答案揭晓！哪家测绘公司泄露了国家秘密？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247531648&idx=2&sn=521bca396c0738f277b781ef105a7c43&chksm=ce222b38f955a22e856189a8ed0aee2e54a669502a86424b8d9733d86147075764543a358325&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247531476&idx=1&sn=06805c10b807bfcf2eb16b2b8c54e96a&chksm=ce222c6cf955a57a063c90ca9ae8f0b5fd113e0837a5ab8617419fb554332dc1c72ce374562f&scene=21#wechat_redirect)  
- # 广东省教育厅群发淫秽短信？API安全问题不容忽视！  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247529131&idx=1&sn=cddee3eb545fa963c1e21790b8645cfd&chksm=ce222513f955ac051703b05141f7c33286296296ad58fa0db1cfede31e80fe36e2f8bedfb51c&scene=21#wechat_redirect)  
- **【头条】中秋夜 | 网安一哥【奇安信】全部站点服务宕机**  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247500168&idx=2&sn=59dcc8abe1a52f4672ba739aaaf32e50&chksm=ce229630f9551f26aa12dfce3efcf450d2db4755d1b873dd91c46f4ab67963a13da0954bd43e&scene=21#wechat_redirect)  
- [【技术解析】| 工商银行美国子公司勒索病毒事件分析](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247500168&idx=2&sn=59dcc8abe1a52f4672ba739aaaf32e50&chksm=ce229630f9551f26aa12dfce3efcf450d2db4755d1b873dd91c46f4ab67963a13da0954bd43e&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247490269&idx=2&sn=050ba319ad33de8c821f3512689546a3&chksm=ce214d65f956c473a1ec2a777448036bc1a87e30166fc6dd62dea59bab9ac626d94f48101f92&scene=21#wechat_redirect)  
- [【专题分享】中国工商银行：数据安全技术平台建设实践](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247490269&idx=2&sn=050ba319ad33de8c821f3512689546a3&chksm=ce214d65f956c473a1ec2a777448036bc1a87e30166fc6dd62dea59bab9ac626d94f48101f92&scene=21#wechat_redirect)  
  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
