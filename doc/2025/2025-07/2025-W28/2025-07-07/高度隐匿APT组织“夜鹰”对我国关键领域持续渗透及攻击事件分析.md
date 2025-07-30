> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501871&idx=1&sn=4ea3266a75e626d57fd15d3e2cb5bcfe

#  高度隐匿APT组织“夜鹰”对我国关键领域持续渗透及攻击事件分析  
Eastmount  娜璋AI安全之家   2025-07-07 04:19  
  
近期，奇安信集团下属的盘古团队在 2025 年马来西亚国家网络防御与安全展览与会议（Malaysia National Cyber Defence & Security Exhibition & Conference）上披露，其自2023年起持续追踪一个名叫“夜鹰（NightEagle）”的APT组织（奇安信内部编号：APT-Q-95、360内部编号：APT-C-78）。  
  
该组织长期针对我国高科技、芯片半导体、量子技术、人工智能与大模型、军工等行业顶尖公司和单位进行网络攻击，目的以窃取情报为主，在窃取情报后，其会快速离开现场并消除痕迹。其攻击活动高度集中于北京时间21:00至次日凌晨6:00（西八区工作时间），展现出高度专业化的作战模式。下面结合奇安信团队梳理的分析报告，一起来剖析“夜鹰”对我国关键领域的攻击事件流程及其技战术。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAJXwOic9RhCsNT0sD3aubwGMNkY53tPu62U2wXzBee9hZC6rSPJjxANw/640?wx_fmt=png&from=appmsg "")  
  
# 一.攻击事件分析  
## 1.异常DNS请求触发警报  
  
奇安信天眼 NDR 系统 QAX-GPT 通过智能研判捕获到异常DNS请求，通过分析发现其伪装为NAS服务商群晖的恶意域名（synologyupdates.com）。该域名采用动态IP隐匿技术：未活跃时解析至127.0.0.1 或 192.168.1.1等局域网IP，通过该手法来避免真正的服务器 IP 暴露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAgibesMzEzckHbFB9JBhJJqT6jFDEuGuaw85LHSczKdqRaYVn5picHLhA/640?wx_fmt=png&from=appmsg "")  
  
然而，客户内网中每4小时一次的规律性请求暴露了攻击行为，并触发客户部署奇安信AISOC的一级警报。通过日志分析发现，在该内网受控主机内出现了恶意进程SynologyUpdate.exe，该进程为定制化的 Go 语言编译的 Chisel 家族木马，攻击者建立了每 4 个小时启动木马的计划任务。  
- 溯源发现受控主机存在计划任务定时执行定制化Chisel木马  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAxKNic3oibSvSJwpOZmvCyc0icHkrQLTEfAnlIfJAyJZLdsRmRfdzWKqxg/640?wx_fmt=png&from=appmsg "")  
## 2.内网穿透与横向移动  
  
攻击者改造开源Chisel内网穿透工具并建立Socks隧道实现内网穿透，通过硬编码凭证连接C&C服务器443端口。AISOC日志分析显示该主机与客户单位内网的Exchange服务器存在异常交互，进一步发现夜鹰组织独有的内存木马特征武器。整个攻击路径如图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGA56FeJ9aLv5Td6GRMXTCtRicjIOH7sqicSW8wyjEg8cXayo35LQQJIrBA/640?wx_fmt=png&from=appmsg "")  
  
关键要点提炼：  
- **攻击入口**  
伪装域名+IP轮转技术规避侦查  
  
- **技术特征**  
定制化Chisel木马实现持久化、硬编码参数绕过及内存穿透  
  
- **攻击演进**  
特种木马 + 未知Exchange漏洞  
  
# 二.技术深度剖析  
  
通过 AISOC 日志分析结果发现客户单位内网的 Exchange 邮服与该主机进行过交互，接着是技术深度剖析。  
## 1.内存木马技术  
  
通过天擎 EDR 对异常进程内存检测，发现了内存木马，其攻击流程如下：  
- **（1）隔离服务器与初始检测**  
该进程被注入了恶意代码（内存马），其不会在磁盘内落地，以避免被杀软或其他工具发现，相关样本处于免杀状态。  
  
- **（2）内存木马加载程序**  
由于攻击者结束后会自动清除内存中木马程序，因此并未获取到内存木马样本。通过天擎 EDR 的磁盘检测功能取到了内存木马的加载程序（App_Web_cn*.dll）。其是攻击者植入 Exchange 服务器 IIS 服务中的 Payload 代码产生的 ASP.NET 预编译 DLL 文件，由.NET 语言编写且具有固定格式的代码结构和函数命名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAz55QBpLkibYJfunTlzEN4bmehnuxzLib0ziajrxORWibpicTiaGCamL1EjYQ/640?wx_fmt=png&from=appmsg "")  
- **（3）内存马执行**  
内存木马加载程序注入DLL写入内存运行后，构建伪装路径“~/auth/lang/cn*.aspx”，攻击通过请求虚拟URL目录来触发执行内存木马程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGA061bPUOvh2nheFcuffqJBasosib1eibdVz2D0CpR2hrOSXrGuBamzcqw/640?wx_fmt=png&from=appmsg "")  
- **（4）目标程序集定位及主函数调用**  
当内存木马程序接收到虚拟URL目录请求后，木马会搜索 Exchange 服务器中名为App_Web_Container_1的程序集，并定位其中恶意类型App_Web_8c9b251fb5b3，最终调用该类型下名为AppWebInit的主体功能函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAicZP7jXz107hZ9pcmb3TmIrLl2ickaGZ9HickLYCZkWoIVypr1Rz47ABA/640?wx_fmt=png&from=appmsg "")  
- **(5) 伪装与地域性攻击特征**  
攻击者通常会使用Web目录“/owa/auth”路径下的子文件夹与文件来创建虚拟URL目录，如“~ /auth/lang/cn.aspx”、“~ /auth/lang/zh.aspx”，在上述虚拟 URL 目录中包含很多国家语言信息标识。我们认为这只是针对中国攻击才会使用 zh、cn 作为虚拟 URL 目录，而攻击其他国家时很有可能是其他国家的缩写，也有可能是 auth 下其他随机路径，其具备一定的定制能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAR8kHpgjRibgF0qvlLIeSqJ1WLt3Z9ESou1sukgdZMQrTOrrEjnSeiaBA/640?wx_fmt=png&from=appmsg "")  
  
关键要点提炼：  
- 注入内存马 → 内存木马加载DLL程序 → 伪装虚拟URL请求执行木马 → 目标程序集定位 → 执行AppWebInit函数 → 地域性定制化  
  
## 2.未知Exchange漏洞  
  
攻击者通过未知0day漏洞获取Exchange服务器的machineKey，利用该Key对Exchange服务器实施反序列化攻击，从而实现向符合Exchange版本的任意服务器注入木马，并且可以远程读取任意人员的邮箱数据。值得注意，攻击者尝试了遍历了市面上Exchange的不同版本号，才锁定了攻击机的版本。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAv8zEA9QBee2KY5ThoXlF9Jf5KN4ggmUMg4nmAEIt3cxpa9Ox42y0fg/640?wx_fmt=png&from=appmsg "")  
  
流量分析显示，攻击者通过构造特殊请求实现全天候远程邮件窃取，天眼流量日志回溯功能发现，相关单位的所有重点目标邮件均被攻击者拖走，时间持续近一年之久。总之，该组织利用0day Exchange漏洞在邮件服务器建立隐蔽通道，实现长期数据渗透。  
  
目前夜鹰组织从攻击入口，到攻击驻留，再到窃密的整体攻击流程已明了，具体流程图如下所示：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGApeoQpn8zKWbcZDbf7EWhGx9pVemMyV9mTXAeVe9pYEl2BIiaQbGZic1g/640?wx_fmt=png&from=appmsg "")  
  
关键要点提炼：  
- Exchange 0day漏洞 → 获取machineKey → 反序列化攻击 → 注入木马  
  
# 三.攻击组织TTPs分析及溯源  
## 1.攻击溯源分析  
  
**（1）基于攻击行为分析的溯源**  
  
通过Chisel木马的活动时间戳（UTC+8 21:00-06:00）与操作规律性（固定且无超时作业），结合时区偏移计算，判定攻击源位于西八区（UTC-8）。该时间模式与北美工作日高度吻合，叠加攻击目标的地缘政治关联性，结合公募目标和利益，归因指向北美的APT组织。  
  
通过该组织注册的域名分析发现，夜鹰组织的攻击目标根据地缘政治动态实时调整，并在中国AI大模型产业崛起后系统性转向大模型应用行业，通过注册行业特征化域名（如仿冒著名Ai绘图工具ComfyUI元素的域名 “comfyupdate.org”）及利用相关系统漏洞实施精准攻击，其技术适配能力与战略聚焦证实该组织为高度关注中国科技发展的顶尖APT威胁。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGA9RuJWcp1vHiaC6f87cy2ZQ5r51cFtDE5FnwneiaIkYUrl08tAHFbe2uA/640?wx_fmt=png&from=appmsg "")  
  
**（2）攻击技战术分析**  
  
针对木马回连域名的非常规的定时回连，以及域名的特征进行扩线，并使用奇安信威胁情报自动化溯源平台进行特征扩线，我们发现了该组织注册的用于攻击我国其他重点单位的恶意域名。经研判，发现每个域名只用于攻击一个单位，同时每个被攻击单位的木马均不一致，再次感叹夜鹰组织资金之雄厚。  
- 每目标独立域名+定制化木马，高成本攻击范式  
  
## 2.TTPs 和 IOCs分析  
  
夜鹰所使用的木马域名包含以下特征：  
- 域名注册商为 Tucows  
  
- 心跳过程中域名解析 IP 地址为 127.0.0.1、0.0.0.0、0.0.0.1、1.0.0.0、114.114.114.114  
  
- 控制过程中域名解析指向美国运营商 IP 地址，其中包含 DigitalOcean 、Akamai、The Constant Company 运营商  
  
- 木马程序由计划任务或服务加载运行，域名请求存在固定的心跳间隔，可能为 2、4、8小时  
  
攻击者使用的最新木马域名，具体情况如下：  

```
app.flowgw.com
cloud.synologyupdates.com
comfyupdate.org
coremailtech.com
dashboard.daihou360.com
e-mailrelay.com
fastapi-cdn.com
fortisys.net
liveupdate.wsupdatecloud.net
mirror1.mirrors-openjdk.org
ms.wsupdatecloud.net
ms-nipre.com
rhel.lvusdupdates.org
sangsoft.net
shangjuyike.com
threatbookav.com
tracking.doubleclicked.com
update.haprxy.org
update.saperpcloud.com
updates.ccproxy.org
wechatutilities.com

```

  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRPrUgLHReM52QhZD8ibWwcGAx6C7gyPsNzb3B4bKulicobYECTw3KePZvibz3rDcnPPpEUy8XKKOZJmA/640?wx_fmt=png&from=appmsg "")  
  
需要注意，若有单位发现有相关域名回连情况，可以对 Exchange 邮件服务器进行检查，确认相关目录下是否有可疑文件，可疑文件是否与正常 IIS 组件功能不匹配，或调用了可疑 API。具体特征如下：  
  
（1）判断 Windows .NET 安装路径 C:\Windows\ Microsoft.NET\Framework64\v4.0.30319\T  
  
emporary ASP.NET Files\ews\ 下是否存在指定格式的文件名，总结成正则表达式判断，是否存在为 cal、zh、cn 的文件名或其他语言版本缩写，且存在后面有三位数字的文件名。  

```
App_Web_cal728.aspx.cdb7cbf8.n5q9vicf.dll
App_Web_cn.aspx.d452ffe4.a0ouixey.dll
App_Web_cn274.aspx.b760cbf5.rcirk_ic.dll
App_Web_cn304.aspx.1221cc01.liudbjfz.dll
App_Web_zh.aspx.b137e928.n546mfkn.dll
App_Web_zh371.aspx.4ed1141f.iecxfmum.dll
App_Web_zh401.aspx.b760cbf5.ek9d9hh4.dll

```

  
（2）判断邮服日志路径 C:\inetpub\logs\LogFiles\W3SVC1\下的邮服日志文件中是否存在包含指定 URL 请求字符串的日志。  

```
POST/owa/auth/logoff.aspx

```

  
（3）判断邮服日志路径 C:\inetpub\logs\LogFiles\W3SVC1\下的邮服日志文件中是否存在包含指定 UserAgent 字符串的日志。  

```
攻击者收取邮件使用的 UserAgent
Microsoft+Office/16.0+(Microsoft+Outlook+Mail+16.0.6416;+Pro)

渗透服务器使用的 UserAgent
Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.0.0+Safari/537.36

```

# 四.总结  
  
夜鹰组织（APT-Q-95）的"快、准、狠"攻击模式印证了顶尖APT组织的典型特征，其利用0day漏洞的隐蔽性凸显了现代防御的核心逻辑：攻击痕迹必然存在。本案证明，防御体系需通过全链路数据完整性（NDR+EDR+日志）实现攻击行为快速发现，并依托威胁情报溯源能力突破未知组织归因瓶颈。  
  
奇安信安全体系通过三大技术架构实现高效防御：多源数据融合（NDR/PDNS/EDR协同）、威胁情报驱动（TIP平台拓线攻击基础设施）、自动化响应（SOAR实现10分钟内隔离-取证-C2封堵）。目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信 NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
（声明：本文内容整理自公开披露内容及相关安全厂商公告）  
  
****  
**参考资料：**  
- [1] 奇安信会议披露内容及相关安全厂商报告. https://www.sohu.com/a/910657004_120932824.  
  
- [2] NightEagle APT Exploits Microsoft Exchange Flaw to Target China’s Military and Tech Sectors. https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html  
  
