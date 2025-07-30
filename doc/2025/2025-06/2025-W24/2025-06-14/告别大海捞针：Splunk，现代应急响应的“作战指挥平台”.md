> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NDg0ODkwMQ==&mid=2247486365&idx=1&sn=04b2472c52329104853cffef7ae928ba

#  告别大海捞针：Splunk，现代应急响应的“作战指挥平台”  
网安布道师  格格巫和蓝精灵   2025-06-14 01:03  
  
#   
  
![](https://mmbiz.qpic.cn/mmbiz_png/9qM7NQ3lGkBvR24spLElt0O8ydJ2eeWTD5VLWrp79as3590jHpdIkZRq5ByKjqM0Em0h37XwU9XuIiau2boqQ7g/640?wx_fmt=png&from=appmsg "")  
#   
> 🚨 警报拉响，你被告知一个核心应用服务器疑似被入侵。你需要面对的，可能是来自全球成百上千台服务器、防火墙、终端的、每秒产生数 G 的海量日志数据。手动登录一台台机器排查？那不是应急响应，那是“信息过载”下的投降。  
> 在现代网络攻防中，速度和可见性决定一切。而 Splunk，正是那个能将数据混沌转化为清晰情报的“作战指挥平台”。今天，就让我们深入了解，专业的应急响应团队是如何利用 Splunk 将被动响应转变为一场高效、精准的“外科手术式”打击。  
  
## 阶段一：“战前准备”：数据是弹药，Splunk 是军火库  
  
在枪声响起前，你的“军火库”里必须备好充足且高质量的“弹药”。在 Splunk 中，“弹药”就是数据。  
### 1. 全面、标准化的数据接入  
  
一个合格的应急响应平台，至少需要接入以下关键数据源，并通过 **Splunk Universal Forwarder (UF)**  
 集中采集：  
- **端点日志 (Endpoint)**  
: Windows Event Logs, **Sysmon**  
, PowerShell 高级日志, macOS/Linux Auditd。这是追踪主机内部行为的基石。  
  
- **网络日志 (Network)**  
: 防火墙、VPN、Web 代理 (Proxy)、DNS 请求日志。它们描绘了流量的走向。  
  
- **流量元数据 (Flow Data)**  
: 使用 **Zeek (原 Bro)**  
 或 **Corelight**  
 等工具采集的网络会话元数据，能提供比防火墙日志丰富得多的上下文。  
  
- **云平台日志 (Cloud)**  
: AWS CloudTrail, Azure Activity Log, Google Cloud Audit Logs。  
  
- **应用日志 (Application)**  
: Web 服务器 (IIS, Nginx), 数据库等应用的访问和错误日志。  
  
### 2. 数据标准化：通用信息模型 (CIM)  
  
**这是 Splunk 的一大“杀手锏”，也是体现“深度”的关键。**  
  
你接入了 Windows 的登录日志 
```
EventCode=4624
```

  
，也接入了 Linux 的登录日志 
```
sshd &#34;Accepted password&#34;
```

  
。当你想查找所有登录成功事件时，难道要写一个超长的 
```
OR
```

  
 查询吗？  
  
不需要！**Splunk CIM (Common Information Model)**  
 允许你将这些不同源、不同格式的数据，映射到一套标准的数据模型上。例如，无论是 Windows 还是 Linux 的登录，都可以被标记为 
```
authentication
```

  
 和 
```
success
```

  
。  
> **CIM 的价值**  
：你的查询不再与具体日志格式绑定，而是与“行为”绑定。你可以用一句简单的 
```
tag=authentication action=success
```

  
 来查找所有成功的登录，极大提高了查询效率和通用性。  
  
### 3. 情报集成与告警设置  
- **威胁情报 (Threat Intelligence)**  
: 将已知的恶意 IP、域名、文件 Hash 等威胁情报源，通过 
```
lookup
```

  
 的方式集成到 Splunk 中。  
  
- **主动告警 (Alerting)**  
: 基于 ATT&CK 框架或历史事件，预先设置好告警规则。例如，“当一个进程访问 lsass.exe 内存时立即告警”、“当审核日志被清除时立即告警”。  
  
## 阶段二：“侦察与分析”：SPL 语言的艺术  
  
当事件发生，Splunk 的 **SPL (Search Processing Language)**  
 就是你手中最锋利的解剖刀。SPL 采用“管道 (pipeline)”式语法，让你可以像搭积木一样，一步步筛选、转换、聚合数据，最终得到答案。  
### 应急响应中的“杀手级” SPL 命令  
- 
```
stats
```

  
: **数据统计的核心**  
。用于聚合和计算。
```
... | stats count by src_ip, user
```

  
 是最常用的命令之一。  
  
- 
```
rare
```

  
 / 
```
top
```

  
: **寻找异常值**  
。快速找出出现频率最低或最高的字段值，非常适合发现“不寻常”的用户、进程或IP。  
  
- 
```
transaction
```

  
: **故事线串联神器**  
。它可以将多个独立的日志事件，根据字段（如 
```
user
```

  
, 
```
session_id
```

  
, 
```
host
```

  
）和时间跨度，串联成一个完整的“事务”。这是还原攻击者操作链的关键。  
  
- 
```
lookup
```

  
: **关联外部情报**  
。将日志中的 IP、域名等与你预先加载的威胁情报库进行匹配。
```
... | lookup ioc_list.csv ip as src_ip OUTPUT reputation
```

  
。  
  
- 
```
eval
```

  
: **动态字段处理**  
。用于进行数学计算、字符串操作，或根据条件创建新字段。  
  
- 
```
geostats
```

  
: **地理位置分析**  
。将 IP 地址在地图上可视化，对于发现异常地理位置的登录非常直观。
```
... | iplocation src_ip | geostats count by Country
```

  
。  
  
## 阶段三：“实战演练”：用 Splunk 还原一次“无文件攻击”  
  
让我们用 SPL 来完整地追踪一次现代攻击。  
  
**场景**  
：HR 部门的一台 PC 触发了“可疑 PowerShell 命令”告警。  
1. **【初步研判】 - 聚焦告警事件**  
  
1. **目标**  
: 查看告警触发的具体 PowerShell 命令。  
  
1. **Splunk 查询**  
:  
  

```
index=powershell sourcetype=&#34;ps_script_block&#34; EventCode=4104 host=&#34;HR-PC-01&#34;
| search &#34;*New-Object*Net.WebClient*DownloadString*&#34;
| table _time, host, user, ScriptBlockText

```

1. **发现**  
: 日志显示，用户 
```
jane.doe
```

  
 的会话在 
```
14:30
```

  
 执行了一段经过混淆的 PowerShell 代码，解码后是从 
```
http://evil-content-delivery.net/loader.ps1
```

  
 下载并执行了脚本。  
  
1. **【影响范围评估】 - 追踪网络连接与父进程**  
  
1. **目标**  
: 找出是哪个进程启动了这个 PowerShell，以及 C2 服务器的 IP 是什么。  
  
1. **Splunk 查询 (利用 transaction 关联 Sysmon 日志)**  
:  
  

```
index=sysmon host=&#34;HR-PC-01&#34; (EventCode=1 OR EventCode=3)
| transaction ProcessGuid maxspan=2m
| where eventcount > 1 AND Image=&#34;*\\powershell.exe&#34; AND DestinationIp != &#34;0.0.0.0&#34;
| table _time, user, ParentImage, Image, CommandLine, DestinationIp, DestinationPort

```

1. **发现**  
: 
```
transaction
```

  
 命令将进程创建 (ID 1) 和网络连接 (ID 3) 事件完美地串联起来。结果显示，父进程是 
```
OUTLOOK.EXE
```

  
（表明是钓鱼邮件附件触发），
```
powershell.exe
```

  
 连接的 IP 是 
```
198.51.100.23
```

  
。  
  
1. **【横向移动检测】 - 查找其他受害者**  
  
1. **目标**  
: 看看 C2 服务器 
```
198.51.100.23
```

  
 是否还与其他内网主机通信。  
  
1. **Splunk 查询**  
:  
  

```
index=netflow OR index=firewall earliest=-24h dest_ip=&#34;198.51.100.23&#34;
| stats count, values(src_ip) as infected_hosts by dest_ip

```

1. **发现**  
: 查询结果显示，除了 
```
HR-PC-01
```

  
，还有另外两台服务器也与该恶意 IP 有通信！调查范围需要立即扩大。  
  
1. **【情报关联】 - 使用 lookup 确认威胁**  
  
1. **目标**  
: 确认 
```
198.51.100.23
```

  
 是否是已知的恶意 IP。  
  
1. **Splunk 查询**  
:  
  

```
index=sysmon EventCode=3 DestinationIp=&#34;198.51.100.23&#34;
| lookup threat_intel_feed.csv ip as DestinationIp OUTPUT description, threat_level

```

1. **发现**  
: 
```
lookup
```

  
 查询返回了结果，
```
threat_level=high
```

  
，
```
description=&#34;Cobalt Strike C2 Server&#34;
```

  
。威胁被证实。  
  
## 阶段四：“超越分析”：联动 SOAR，实现自动化响应  
  
应急响应的最终目标是**更快、更准**  
。Splunk SOAR (原 Phantom) 平台让这成为可能。  
- **SOAR (安全编排、自动化与响应)**  
: 它可以将重复性的应急响应任务编写成**剧本 (Playbook)**  
 并自动执行。  
  
- **工作流示例**  
:  
  
- **自动富化**  
: 调用 VirusTotal API 查询恶意 IP 和文件 Hash 的信誉。  
  
- **自动响应**  
: 调用防火墙 API，将恶意 IP 加入黑名单；调用 EDR (终端检测与响应) API，隔离受感染的主机。  
  
- **自动通知**  
: 在 JIRA 中创建工单，并将事件概要发送到安全团队的 Slack 频道。  
  
- Splunk Enterprise Security (ES) 的告警规则被触发（如“检测到 Cobalt Strike C2 连接”）。  
  
- 自动将告警发送给 Splunk SOAR。  
  
- SOAR 启动剧本：  
  
> SOAR 将分析师从繁琐的手动操作中解放出来，让他们能专注于更高级的威胁狩猎和决策。  
  
## 结语  
  
Splunk 不仅仅是一个日志搜索工具，它是一个完整的、可扩展的数据平台，深刻地改变了现代安全运营和应急响应的模式。  
  
它将 IR 从一场混乱、高压的“救火行动”，转变为一场**数据驱动、流程清晰、甚至可以部分自动化的“精确制导”**  
。掌握 Splunk，意味着你掌握了在海量数据中洞察真相的能力，也掌握了在与高级威胁的对抗中，赢得时间和主动权的关键。  
  
  
