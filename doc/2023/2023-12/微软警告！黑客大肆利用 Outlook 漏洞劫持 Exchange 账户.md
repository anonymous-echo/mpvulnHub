#  微软警告！黑客大肆利用 Outlook 漏洞劫持 Exchange 账户   
 网络安全应急技术国家工程中心   2023-12-06 15:11  
  
Bleeping Computer 网站消息，微软威胁情报团队近期发布警告称，疑似具有俄罗斯国家背景的网络攻击组织 APT28（又名 "Fancybear "或 "Strontium"）正在积极利用 CVE-2023-23397 Outlook 漏洞，劫持微软 Exchange 账户并窃取敏感信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibVqyk3waPEI8NUmDxrhia3Wyj6N6xUr3jCAbrLKZoUNxNPWb74TM3Xib1rxyoDycHcZztoZtDfvVyQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
此外，微软威胁情报团队强调 APT28 在网络攻击活动中还利用了 WinRAR 中存在的 CVE-2023-38831 漏洞和 Windows MSHTML 中的 CVE-2021-40444 漏洞，其瞄准的攻击目标主要包括美国、欧洲和中东的政府、能源、交通和其他重要组织。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibVqyk3waPEI8NUmDxrhia3WeWegeDibLyAScBldres0Dr6gf9z1sq2eicjaIZIgp7E3iaDjXic4CvZqiaA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
# Outlook 漏洞利用背景  
  
CVE-2023-23397 是 Windows 上 Outlook 中一个关键权限提升 (EoP) 漏洞，APT28 威胁组织自 2022 年 4 月以来一直在利用该漏洞，通过特制的 Outlook 笔记窃取 NTLM 哈希值，迫使目标设备在不需要用户交互的情况下向攻击者控制的 SMB 共享进行身份验证。  
  
不仅如此，APT28 威胁组织还通过提升系统权限，在受害目标的环境中进行横向移动，并更改 Outlook 邮箱权限，从而实施有针对性的电子邮件盗窃。更糟糕的是，尽管后来提供了安全更新和缓解建议，但仍然存在很大的攻击面。  
  
Recorded Future 在 6 月份警告说，APT28 威胁组织很可能利用 Outlook 漏洞攻击乌克兰的重要组织，10 月份，法国网络安全局（ANSSI）又披露俄罗斯黑客利用漏洞攻击了法国的政府实体、企业、大学、研究机构和智库。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibVqyk3waPEI8NUmDxrhia3W87SicDkFicPZGBjnhqQBzlGRqnhicMnV2syibMuQHDhcpWooZuvKjaichmA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 网络攻击活动仍在持续进行中  
  
微软发布最新警告表示，GRU 黑客仍在利用 CVE-2023-38831 安全漏洞进行网络攻击，因此仍有系统易受关键 EoP 漏洞的影响。此外，微软还提到波兰网络指挥中心（DKWOC）在帮助检测和阻止网络攻击方面所采取的措施，DKWOC 发布一篇文章，详细描述了 APT28 如何利用 CVE-2023-38831 安全漏洞，进行网络攻击活动。  
  
强烈建议用户立即采取以下安全措施（按优先级排列）：  
> 应用针对 CVE-2023-23397 及其旁路 CVE-2023-29324 的可用安全更新。  
> 使用 Microsoft 提供的此脚本检查是否有 Exchange 用户成为攻击目标。  
> 重置受攻击用户的密码，并为所有用户启用 MFA（多因素身份验证）。  
> 通过阻止所有入站 IP 地址与端口 135 和 445 的连接来限制 SMB 流量  
> 禁用环境中的 NTLM。  
  
  
最后，网络安全专家指出，鉴于 APT28 是一个“资源丰富”、适应性强的网络威胁攻击组织，常规网络防御措施很难起到效果，最有效的防御策略是减少所有接口的攻击面，并确保所有软件产品定期更新最新的安全补丁。  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/microsoft/russian-hackers-exploiting-outlook-bug-to-hijack-exchange-accounts/  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
