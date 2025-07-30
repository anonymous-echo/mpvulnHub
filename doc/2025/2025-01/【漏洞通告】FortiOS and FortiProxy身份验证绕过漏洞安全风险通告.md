#  【漏洞通告】FortiOS and FortiProxy身份验证绕过漏洞安全风险通告   
 嘉诚安全   2025-01-16 07:28  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Fortinet官方发布安全公告，确认其下一代防火墙产品FortiGate（FortiOS）和代理产品 FortiProxy中存在一个高危的认证绕过漏洞，漏洞编号为：  
CVE-2024-55591。  
  
  
FortiOS是Fortinet公司核心的网络安全操作系统，广泛应用于FortiGate下一代防火墙，为用户提供防火墙、VPN、入侵防御、应用控制等多种安全功能。FortiProxy则是Fortinet提供的企业级安全代理产品，主要用于内容过滤、Web访问控制和数据安全防护等场景。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，已发现被  
**在野利用**  
。  
攻击者可通过向开放在互联网上的FortiGate管理接口（HTTPS或CLI Web Console）发送特定探测或恶意请求来触发该漏洞，从而在设备上执行多种非法操作。攻击者成功利用该漏洞可在FortiGate/FortiProxy设备上执行任意管理操作，包括创建或重置管理员账户、读取或修改防火墙策略、配置SSL VPN并进一步进行网络横向移动等。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
FortiOS 7.0.* <= 7.0.16  
  
FortiProxy 7.2.* <= 7.2.12  
  
FortiProxy 7.0.* <= 7.0.19  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
官方已发布修复方案，受影响的用户建议更新至安全版本：  
  
FortiGate（FortiOS） 7.0.17及更高版本  
  
FortiProxy 7.2.13及更高版本  
  
FortiProxy 7.0.20及更高版本  
  
参考链接：  
  
https://docs.fortinet.com/upgrade-tool  
  
https://www.fortiguard.com/psirt/FG-IR-24-535  
  
https://arcticwolf.com/resources/blog/console-chaos-targets-fortinet-fortigate-firewalls/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
