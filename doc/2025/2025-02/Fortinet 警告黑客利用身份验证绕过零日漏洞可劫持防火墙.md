#  Fortinet 警告黑客利用身份验证绕过零日漏洞可劫持防火墙   
Rhinoer  犀牛安全   2025-02-11 05:17  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczhKtn4sMibZKrSya8PubFFnHdkcho4hTkZiaDJjReMibwYsKpocB42uYvQ/640?wx_fmt=png&from=appmsg "")  
  
攻击者正在利用 FortiOS 和 FortiProxy 中新的身份验证绕过零日漏洞劫持 Fortinet 防火墙并侵入企业网络。  
  
此安全漏洞（编号为CVE-2024-55591）影响 FortiOS 7.0.0 至 7.0.16、FortiProxy 7.0.0 至 7.0.19 以及 FortiProxy 7.2.0 至 7.2.12。成功利用此漏洞后，远程攻击者可通过向 Node.js websocket 模块发出恶意请求来获取超级管理员权限。  
  
Fortinet 表示，在野利用零日漏洞的攻击者会在受感染的设备上创建随机生成的管理员或本地用户，并将他们添加到现有的 SSL VPN 用户组或新添加的用户组中。  
  
他们还被发现添加或更改防火墙策略和其他设置，并使用之前创建的恶意账户登录 SSLVPN“以建立通往内部网络的隧道”。  
  
虽然该公司没有提供有关此次活动的更多信息，但网络安全公司 Arctic Wolf 周五发布了一份包含相应入侵指标 (IOC) 的报告，报告称，自 11 月中旬以来，具有暴露在互联网上的管理界面的 Fortinet FortiGate 防火墙一直受到攻击。  
  
Arctic Wolf Labs 表示：“此次活动涉及防火墙管理界面上的未经授权的管理登录、新账户的创建、通过这些账户进行 SSL VPN 身份验证以及其他各种配置更改。”  
  
虽然初始访问向量尚未得到明确确认，但零日漏洞的可能性很高。组织应尽快禁用公共接口上的防火墙管理访问。  
- 在今天的公告中，Fortinet 还建议管理员禁用 HTTP/HTTPS 管理界面或限制哪些 IP 地址可以通过本地策略访问管理界面，作为一种解决方法。  
  
- Arctic Wolf 还提供了此次 CVE-2024-55591 大规模利用活动的时间表，称其包括四个阶段：  
  
- 漏洞扫描（2024年11月16日至2024年11月23日）  
  
- 侦察（2024 年 11 月 22 日至 2024 年 11 月 27 日）  
  
- SSL VPN 配置（2024 年 12 月 4 日至 2024 年 12 月 7 日）  
  
- 横向移动（2024 年 12 月 16 日至 2024 年 12 月 27 日）  
  
该网络安全公司补充道：“虽然此次活动中使用的初始访问载体尚未确认，但 Arctic Wolf Labs 高度确信，考虑到受影响组织和受影响固件版本的压缩时间线，零日漏洞很可能被大规模利用。”  
  
鉴于入侵行为在技术和基础设施方面存在细微差别，可能有多个个人或团体参与了此次活动，但 jsconsole 的使用是所有攻击行为的共同点。  
  
Fortinet 和 Arctic Wolf 共享几乎相同的 IOC，指出您可以检查日志中的以下条目以确定设备是否成为攻击目标。  
  
通过漏洞登录后，日志会显示一个随机的源IP和目标IP：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczibAfseM1p1NSWz1EJSyRWMxVdBbF3oH04YHibIBfibRINCHPtZYn0COfw/640?wx_fmt=png&from=appmsg "")  
  
Arctic Wolf 表示，它于 2024 年 12 月 12 日向 Fortinet 通报了有关攻击的情况，并于 2024 年 12 月 17 日收到 FortiGuard Labs PSIRT 的确认，称该活动已为人所知且正在调查中。  
  
今天，Fortinet 还发布了针对严重硬编码加密密钥漏洞 ( CVE-2023-37936 ) 的安全补丁。此漏洞允许拥有密钥的远程、未经身份验证的攻击者通过精心设计的加密请求运行未经授权的代码。  
  
12 月，Volexity 报道称，中国黑客使用名为“DeepData”的定制后开发工具包利用 Fortinet 的 FortiClient Windows VPN 客户端中的零日漏洞（无 CVE ID）窃取凭据。  
  
两个月前，Mandiant 透露，Fortinet FortiManager 的一个漏洞“FortiJump”（追踪编号为 CVE-2024-47575）已被利用作为零日漏洞，自 6 月份以来入侵了超过 50 台服务器。  
  
  
信息来源：BleepingComputer  
  
