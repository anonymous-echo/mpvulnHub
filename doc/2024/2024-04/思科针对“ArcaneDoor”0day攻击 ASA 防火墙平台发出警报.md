#  思科针对“ArcaneDoor”0day攻击 ASA 防火墙平台发出警报   
 军哥网络安全读报   2024-04-25 07:57  
  
**导****读**  
  
  
  
科技巨头思科周三警告称，国家支持的专业黑客团队正在利用其 ASA 防火墙平台中的至少两个  
0day  
漏洞，在电信和能源部门网络上植入恶意软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFrQNzocgzrPXzjExiaut0rODYibJMJXERk5wiabtHibmwkHuPiaRR93lHoKRyFaTz3sjG148YibfppZL9Q/640?wx_fmt=png&from=appmsg "")  
  
  
根据思科 Talos 的一份报告(  
https://blog.talosintelligence.com/arcanedoor-new-espionage-focused-campaign-found-targeting-perimeter-network-devices/  
)，攻击者瞄准运行思科自适应安全设备 (ASA) 或思科 Firepower 威胁防御
(FTD) 产品的某些设备中的软件缺陷，植入恶意软件、执行命令，并可能从受感染的设备中窃取数据。  
  
  
该活动标记为
ArcaneDoor，利用思科产品中两个已记录的软件漏洞（CVE-2024-20353 和
CVE-2024-20359），但思科公司的恶意软件猎人仍然不确定攻击者是如何入侵的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFrQNzocgzrPXzjExiaut0rONBlQJgRkibGMfLTEPVBO6TicEdLppRSGszrL6D5rlLDBevX3HEnMjmJQ/640?wx_fmt=png&from=appmsg "")  
  
“我们尚未确定此次活动中使用的初始访问向量。迄今为止，我们尚未发现预身份验证利用的证据。”思科
Talos 表示。  
  
  
“ArcaneDoor
是一项由国家背景的黑客组织针对多个供应商的外围网络设备发起攻击的最新例子。对于这些攻击者来说，外围网络设备是针对间谍活动的完美入侵点。”思科解释说，并指出，在这些设备上获得立足点可以让攻击者直接进入组织、重新路由或修改流量并监控网络通信。  
  
  
思科表示，一位未透露姓名的客户于
2024 年初向其 PSIRT 团队通报了 ASA 防火墙产品的“安全问题”，启动了一项调查，最终发现了黑客活动（Talos 追踪为
UAT4356，微软威胁情报中心追踪为 STORM-1849） 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFrQNzocgzrPXzjExiaut0rOMzcQoL544a8fICkwlIB5LWfVu2bbs6sMNfVCPbxFK1a9CIrggvVByw/640?wx_fmt=png&from=appmsg "")  
  
UAT4356基础设施  
  
  
该公司表示：“该攻击者使用了定制工具，表现出对间谍活动的明确关注以及对其目标设备的深入了解，这是成熟的国家资助攻击者的标志。”  
  
  
思科表示，它观察到黑客团队部署了两个后门，这些后门共同用于针对目标进行恶意操作，其中包括配置修改、侦察、网络流量捕获/渗透以及潜在的横向移动。  
   
  
  
该公司警告称：“思科与受害者和情报合作伙伴合作，发现了一个复杂的攻击链，该攻击链用于植入定制恶意软件并在一小部分客户中执行命令。”  
  
  
思科研究人员表示，网络遥测和情报合作伙伴提供的信息表明，黑客有兴趣刺探微软和其他供应商的网络设备。  
  
  
思科表示：“无论您的网络设备提供商是谁，现在都是确保设备正确修补、登录到中央安全位置并配置为具有强大的多因素身份验证
(MFA) 的时候了。”  
  
  
**参考链接：**  
  
****  
https://www.securityweek.com/cisco-raises-alarm-for-arcanedoor-zero-days-hitting-asa-firewall-platforms/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
