#  【安全圈】SuperBlack 攻击者利用两个 Fortinet 漏洞部署勒索软件   
 安全圈   2025-03-14 19:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
勒索软件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXPQVSDickwAHl8MHSg817kmBrWPwNnP3cIjfe5tMSiaFx2NGdDgNzCbF9Q/640?wx_fmt=png&from=appmsg "")  
  
2025 年 1 月底至 3 月初，Forescout 旗下 Vedere 实验室的网络安全研究人员发现了一系列利用关键Fortinet 漏洞的复杂入侵行为。  
  
此次攻击被归咎于一个新发现的威胁行为者“Mora_001”，最终导致部署了一种名为“SuperBlack”的定制勒索软件。  
  
Mora_001 展示了一种系统的入侵网络的方法，首先是利用两个关键的 Fortinet 漏洞：  
CVE-2024-55591 和 CVE-2025-24472。  
  
这些漏洞影响7.0.16 之前的FortiOS 版本，并允许未经身份验证的攻击者在具有暴露管理界面的易受攻击的设备上获得超级管理员权限。  
  
研究人员在野外观察到两种不同的利用方法，始于 2025 年 1 月 27 日概念验证漏洞公开发布后仅 96 小时。  
  
第一种方法是利用 jsconsole 接口，利用伪造的 IP 地址（通常是 127.0.0.1、8.8.8.8 或其他可识别的地址）利用 WebSocket 漏洞。  
  
第二种方法采用针对相同潜在漏洞的直接 HTTPS 请求。  
## 持久性技术  
  
获得初始访问权限后，Mora_001 通过几种复杂的机制建立了持久性。  
  
攻击者不断创建本地系统管理员帐户，并使用旨在与合法服务相混淆的名称，包括“forticloud-tech”、“fortigate-firewall”和“adnimistrator”（故意拼写错误为“administrator”）。  
  
一种特别阴险的技术是创建自动化任务，以确保即使在补救尝试之后仍然能够持久。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliajjvdWakRvnUcaa8z3dOXPk7fXiabOejoiakdezPa5XwywAClib9iaTib4B5VFc5NF9WxD1ibWODTYJaZQ/640?wx_fmt=png&from=appmsg "")  
  
例如，攻击者配置了每日脚本自动化任务，如果管理员帐户被删除，该任务将自动重新创建管理员帐户。  
  
其中一个脚本包含重新创建具有 super_admin 权限和预定密码的“forticloud-sync”用户的命令。  
  
在具有高可用性 (HA) 配置的环境中，Mora_001 强制同步以将受损配置传播到同一集群内的其他防火墙，从而有效地将其后门帐户传播到多个设备。  
  
建立持久性后，Mora_001 使用 FortiGate 仪表板进行了广泛的侦察，以收集环境情报。  
  
攻击者访问了状态、安全、网络以及用户和设备仪表板，以识别横向移动的潜在路径。  
  
在具有 VPN 功能的环境中，威胁行为者创建了额外的VPN 用户帐户，其名称类似于合法帐户，但进行了细微的修改，例如在末尾添加了一位数字（例如“xxx1”）。  
  
然后将这些帐户添加到 VPN 用户组，以便将来访问网络，同时逃避随意的管理审查。  
## 网络遍历方法  
  
对于横向移动，Mora_001 利用了多种技术：  
1. 使用窃取的 VPN 凭证访问内部网络。  
  
  
2. 利用高可用性 (HA) 配置传播来破坏其他防火墙。  
  
3 . 在配置为与Active Directory  
同步时，通过 TACACS+ 或 RADIUS 滥用身份验证基础架构。  
  
4 . 使用 Windows 管理规范 (WMIC) 进行远程系统发现和执行。  
  
5 . 利用 SSH 访问其他服务器和网络设备。  
攻击者优先考虑高价值目标，特别是文件服务器、身份验证服务器、域控制器和数据库服务器。  
  
Mora_001 不会不加区别地加密整个网络，而是有选择地针对包含敏感数据的系统，首先关注数据泄露，然后再开始加密。  
## SuperBlack 勒索软件  
  
Mora_001 部署的勒索软件被研究人员称为“SuperBlack”，与 LockBit 3.0（也称为 LockBit Black）非常相似，但进行了特定的修改。  
  
主要区别在于赎金记录的结构以及是否包含自定义数据泄露可执行文件。  
  
尽管表面上发生了变化，勒索软件仍然与LockBit 生态系统保持着紧密的联系。  
  
赎金记录中包含一个 Tox 聊天   
ID  
  
（DED25DCB2AAAF65A05BEA584A0D1BB1D55DD2D8BB4185FA39B5175C60C8DDD0C0A7F8A8EC815），该 ID 之前曾与 LockBit 3.0 操作有关。  
  
该说明保留了 LockBit 的 HTML 模板结构，但删除了通常会将其标识为 LockBit 勒索软件的明确品牌元素（例如标题）。  
  
研究人员在 VirusTotal 上发现了具有类似勒索记录的其他样本，这些样本将 SuperBlack 连接到之前与 BlackMatter、LockBit 和 BlackMatte 勒索软件相关的导入哈希值。  
  
这一证据表明，Mora_001 要么是 LockBit 的现任或前任附属机构，利用其泄露的构建器，要么是重新利用 LockBit 基础设施和工具的独立威胁行为者。  
## 基础设施与模式  
  
SuperBlack 的主要可执行文件负责处理加密过程并下载其他组件，包括指定为“WipeBlack”的擦除器模块。  
  
此组件在之前与 LockBit 和 BrainCipher 相关的勒索软件事件中已经出现过，而这些事件又与 SenSayQ、EstateRansomware 和 RebornRansomware 存在联系。  
  
该擦除器采用了复杂的反取证技术，包括动态解析Windows API  
以阻碍静态分析和使用命名管道执行命令。  
  
加密完成后，它使用 1MB 缓冲区和 0x3105DFDE 的解密密钥用随机数据覆盖勒索软件可执行文件，从而有效地抹去初始感染的证据。  
  
Mora_001 的操作与特定基础设施有关，包括 IP 地址 185.147.124.34，据观察该地址对多个边缘设备执行暴力破解尝试。  
  
该 IP 地址托管一个名为“VPN Brute v1.0.2”的工具，这是一款俄语实用程序，旨在强制破解各种 VPN 服务和边缘设备的凭证。  
  
VPN Brute 工具针对多个平台，包括：  
- 远程桌面 Web 访问 (RDWeb)  
  
- PulseSecure（工具中称为“Dana”）  
  
- Outlook Web 访问 (OWA)  
  
- Palo Alto Networks GlobalProtect  
  
- 飞塔  
  
- 思科  
  
- F5 网络 BIG-IP  
  
- Citrix  
  
研究人员发现了另外 15 个运行 VPN Brute 版本的 IP 地址，新版本提供了增强的功能，例如在成功发现凭证后继续暴力破解、自定义用户名和密码组合以及蜜罐检测功能。  
  
Mora_001 活动强调了利用边界安全设备进行初始访问的趋势日益增长，攻击者迅速利用已披露的漏洞进行武器化。  
  
截至撰写报告时，美国（7,677）、印度（5,536）和巴西（3,201）拥有最多的暴露FortiGate 防火墙，因此它们特别容易受到这些攻击。  
## 缓解措施  
  
为了防范 Mora_001 和类似威胁，组织应实施以下措施：  
  
1. 立即应用 FortiOS 更新来修复易受攻击的系统，以解决 CVE-2024-55591 和 CVE-2025-24472 问题。2. 尽可能禁用外部管理接口，限制管理访问。3. 定期审核管理员帐户，以识别和删除未经授权的用户。4. 检查自动化设置中是否存在可疑任务，特别是计划每天或下班时间运行的任务。5. 检查 VPN 用户和组，查看合法用户名或最近创建的帐户是否有细微变化。6. 启用全面日志记录，包括 CLI 审计日志、HTTP/S 流量日志、网络策略服务器审计和身份验证系统审计。  
  
Mora_001 活动代表了勒索软件领域的一次复杂演变，将机会性利用与有针对性的数据盗窃和选择性加密相结合。  
  
在保持与 LockBit 等成熟勒索软件生态系统的运营联系的同时，Mora_001 开发了独特的策略和工具，使其成为独特的威胁行为者。  
  
部署 Fortinet 的组织应优先修补易受攻击的设备并实施建议的缓解措施以防范这种新出现的威胁。  
  
新披露的漏洞被迅速利用，凸显了及时更新安全并进行全面网络监控的重要性，以便在复杂攻击实现其目标之前检测并应对这些攻击。  
  
来源：https://cybersecuritynews.com/superblack-actors-exploiting-two-fortinet-vulnerabilities/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】PHP XXE 注入漏洞让攻击者读取配置文件和私钥](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=2&sn=8209e2048ee474d6b91f16029aa9c134&scene=21#wechat_redirect)  
  
  
  
[【安全圈】施乐打印机漏洞使攻击者能够从 LDAP 和 SMB 中获取身份验证数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=3&sn=a464bcdd8889a7e0e65921296df9fdd8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】谷歌警告 Chromecast 用户不要恢复出厂设置](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068467&idx=4&sn=7af960ec5a3791a46142d0250eee6895&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】美国政府称 2024 年美国人因欺诈损失创纪录 125 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=1&sn=7aa71495a16a8590c5a5dbaf2a299a09&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
