#  FICORA、CAPSAICIN 僵尸网络利用旧 D-Link 路由器漏洞发起 DDoS 攻击   
三沐  三沐数安   2024-12-31 08:25  
  
Mirai 和 Keksec 僵尸网络变体正在利用 D-Link 路由器中的关键漏洞。了解影响、受影响的设备以及如何保护自己免受这些攻击。  
- **僵尸网络活动增加**：新的“FICORA”和“CAPSAICIN”僵尸网络、Mirai 和 Kaiten 的变种活动激增。  
- **利用漏洞**：攻击者利用已知的 D-Link 路由器漏洞（例如 CVE-2015-2051、CVE-2024-33112）执行恶意命令。  
- **僵尸网络功能**：两个僵尸网络都使用 shell 脚本、以 Linux 系统为目标、杀死恶意软件进程并发动 DDoS 攻击。  
- **全球影响**：FICORA 针对了多个国家，而 CAPSAICIN 则主要针对东亚，该地区的活跃程度持续了两天多。  
- **缓解措施**：建议定期更新固件并进行强大的网络监控以防止攻击。  
FortiGuard Labs 观察到 2024 年 10 月和 11 月两个僵尸网络“FICORA”和“CAPSAICIN”的活动激增。FortiGuard Labs 的威胁研究团队在其与 Hackread.com 独家分享的博客文章中解释说，这些僵尸网络是著名的 Mirai和Kaiten僵尸网络的变体，可以执行恶意命令。  
  
进一步调查显示，这些僵尸网络的传播涉及利用 D-Link 漏洞，允许远程攻击者通过家庭网络管理协议 (HNAP) 接口上的 GetDeviceSettings 操作执行恶意命令。   
  
这些漏洞包括CVE-2015-2051、CVE-2019-10891、CVE-2022-37056和CVE-2024-33112。这些 CVE 代表攻击者利用的 D-Link 路由器漏洞的具体实例。它们通常涉及 HNAP 处理用户输入和身份验证的方式的缺陷。攻击者使用 HNAP 接口来传播恶意软件，而这一弱点在近十年前首次暴露。  
  
受影响的平台包括D-Link DIR-645 有线/无线路由器 Rev. Ax、D-Link DIR-806 设备以及 D-Link GO-RT-AC750 GORTAC750_revA_v101b03 和 GO-RT-AC750_revB_FWv200b02。根据 FortiGuard Labs IPS 遥测，僵尸网络的严重性级别较高，并通过较早的攻击进行传播。  
  
FICORA 僵尸网络是一种恶意软件，它针对多种 Linux 架构，并使用ChaCha20加密算法对其配置进行编码。此外，它的功能还包括暴力攻击功能，嵌入带有十六进制 ASCII 字符的 shell 脚本以识别和杀死其他恶意软件进程，以及使用 UDP、TCP 和 DNS 等协议的 DDoS 攻击功能。  
  
根据 FortiGuard 实验室威胁研究团队的博客文章，该僵尸网络下载了一个名为“multi”的 shell 脚本，该脚本使用 wget、ftpget、curl 和 tftp 等各种方法来下载实际的恶意软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Szloeso1r8ia3MWhPq8uYKHCIWU0pAYFVSrZYZoiaEncqRyoPwerNNuGURu6uQIOzvbJ4KoHhs03TITDGGC0p0Lg/640?wx_fmt=jpeg&from=appmsg "")  
  
FICORA 僵尸网络攻击针对全球多个国家，由来自荷兰服务器的攻击者触发。另一方面，与 FICORA 不同的是，CAPSAICIN 攻击仅在 2024 年 10 月 21 日至 22 日两天内活跃，并且针对东亚国家。   
  
然而，与 FICORA 一样，它也表现出多样化的功能，包括下载名为“bins.sh”的 shell 脚本、针对多种 Linux 架构、终止已知的僵尸网络进程、与其 C2 服务器建立连接、发送受害者主机信息以及提供DDoS 攻击功能。  
  
尽管此次攻击中利用的漏洞已为人所知近十年，但这些攻击仍然很普遍，这令人担忧。尽管如此，为了降低D-Link 设备被僵尸网络攻击的风险，建议定期更新固件并保持全面的网络监控。  
  
FortiGuard 实验室的研究员 Vincent Li 总结道：“FortiGuard 实验室发现‘FICORA’和‘CAPSAICIN’通过此漏洞传播。因此，对于每个企业来说，定期更新设备内核并保持全面监控至关重要。”  
  
  
