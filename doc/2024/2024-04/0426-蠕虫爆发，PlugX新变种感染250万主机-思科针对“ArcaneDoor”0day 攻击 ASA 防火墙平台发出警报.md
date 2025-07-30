#  0426-蠕虫爆发，PlugX新变种感染250万主机-思科针对“ArcaneDoor”0day 攻击 ASA 防火墙平台发出警报   
网络盾牌  网络盾牌   2024-04-26 14:36  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvicR6UW5VyOsMWAGZwZwSYxCicu29CdiaKlE6lI427wYB4YUn2kzWyKA3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点击上方蓝色文字关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvACH7GqBbXsTicZ0dBuiaib2oAxTwiaq9YHJzaxoZrt05vE99micg5dCNv4A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**今日全球网安资讯摘要******  
  
# 特别关注  
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
- #   
#   
# 蠕虫爆发，PlugX新变种感染250万主机  
  
- #   
#   
# 思科针对“ArcaneDoor”0day 攻击 ASA 防火墙平台发出警报  
  
- #   
#   
# 因发起网络攻击，美国悬赏 1000 万美元逮捕四名伊朗公民  
  
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
  
  
**特别关注**  
#   
#   
# 蠕虫爆发，PlugX新变种感染250万主机  
#   
#   
#   
#   
  
****#   
#   
#   
  
**标签:蠕虫病毒**  
  
近日，网络安全公司Sekoia发现蠕虫病毒PlugX的新变种已经在全球范围感染了超过250万台主机。  
  
老牌恶意软件藏身U盘  
  
PlugX是有着十多年历史的老牌恶意软件（蠕虫病毒），最早可追溯到2008年，最初只被亚洲的黑客组织使用，主要针对政府、国防、技术和政治组织。2015年发生代码泄露后，PlugX被改造成大众化的流行黑客工具，被全球网络犯罪分子广泛使用，其中一些黑客组织将其与数字签名软件结合，用于实施侧加载加密的攻击载荷。  
  
PlugX的最新变种增加了蠕虫组件，可通过U盘感染物理隔离系统。2023年派拓网络公司（PaloAltoNetwork）的Unit42团队在响应BlackBasta勒索软件攻击时，在VirusTotal扫描平台上发现了PlugX的一个新变种可通过U盘传播，并能将目标敏感文件隐藏在U盘中。  
  
2023年3月，Sophos也报告了这种可通过USB自我传播的PlugX新变种，并称其已经“传播了半个地球”。  
  
全球250万台主机中招，中美都是重灾区  
  
六个月前，Seqoia的研究人员发现了一个被黑客废弃的PlugX恶意软件变种（Sinkhole）的命令和控制(C2)服务器。  
  
在Seqoia联系托管公司并请求控制IP后，研究人员花费7美元获取了该服务器的IP地址45.142.166.xxx，并使用该IP获得了对服务器的shell访问权限。  
  
分析人员设置了一个简单的Web服务器来模仿原始C2服务器的行为，捕获来自受感染主机的HTTP请求并观察流量的变化。  
  
C2服务器的操作记录显示，每天有9-10万个主机发送请求，六个月内全球有近250万个独立IP连接到该服务器（下图）：  
  
研究人员发现，PlugX已传播到全球170个国家，但集中度较高，15个国家占感染总数的80%以上，其中尼日利亚、印度、中国、伊朗、印度尼西亚、英国、伊拉克和美国是重灾区。  
  
研究人员强调，由于被废弃的PlugXC2服务器没有唯一标识符，这导致受感染主机的统计数字可能并不十分准确，因为：  
- 许多受感染的工作站可以通过相同的IP地址连接  
  
- 由于采用动态IP寻址，一个受感染系统可以连接多个IP地址  
  
- 许多连接是通过VPN服务进行的，这可能使来源国家/地区的数据失真  
  
两种杀毒方法  
  
Sekoia建议各国网络安全团队和执法机构采取两种杀毒方法。  
  
第一种方法是发送PlugX支持的自删除命令，该命令应将其从计算机中删除，而无需执行其他操作。但需要注意的是，因为PlugX新变种可通过USB设备传播，第一种方法无法清除这些“离线”病毒。即使从主机中删除了恶意软件，仍然存在重新感染的风险。  
  
第二种方法较为复杂，需要在受感染的计算机上开发和部署自定义有效负载，从系统以及与其连接的受感染USB驱动器中删除PlugX。  
  
Sekoia还向各国国家计算机紧急响应小组(CERT)提供了执行“主权消毒”所需的信息。  
  
信源：https://blog.sekoia.io/unplugging-plugx-sinkholing-the-plugx-usb-worm-botnet/  
  
**安全资讯**  
#   
#   
# 思科针对“ArcaneDoor”0day 攻击 ASA 防火墙平台发出警报  
#   
#   
#   
#   
#   
  
****#   
#   
#   
#   
  
**标签： 0day 漏洞，恶意软件**  
  
科技巨头思科周三警告称，国家支持的专业黑客团队正在利用其 ASA 防火墙平台中的至少两个 0day 漏洞，在电信和能源部门网络上植入恶意软件。  
  
根据思科 Talos 的一份报告，攻击者瞄准运行思科自适应安全设备 (ASA) 或思科 Firepower 威胁防御 (FTD) 产品的某些设备中的软件缺陷，植入恶意软件、执行命令，并可能从受感染的设备中窃取数据。  
  
该活动标记为 ArcaneDoor，利用思科产品中两个已记录的软件漏洞（CVE-2024-20353 和 CVE-2024-20359），但思科公司的恶意软件猎人仍然不确定攻击者是如何入侵的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jeDQCJpl84DSrU7oXLREyX82Oq24VDlFACZIIHYWrmIQffKgjzicY4ynBHKgd0VmXUJaBaJc2PISVGNZmfKFeNw/640?wx_fmt=png&from=appmsg "")  
> “我们尚未确定此次活动中使用的初始访问向量。迄今为止，我们尚未发现预身份验证利用的证据。”思科 Talos 表示。  
> “ArcaneDoor 是一项由国家背景的黑客组织针对多个供应商的外围网络设备发起攻击的最新例子。对于这些攻击者来说，外围网络设备是针对间谍活动的完美入侵点。”思科解释说，并指出，在这些设备上获得立足点可以让攻击者直接进入组织、重新路由或修改流量并监控网络通信。  
  
  
思科表示，一位未透露姓名的客户于 2024 年初向其 PSIRT 团队通报了 ASA 防火墙产品的“安全问题”，启动了一项调查，最终发现了黑客活动（Talos 追踪为 UAT4356，微软威胁情报中心追踪为 STORM-1849） 。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jeDQCJpl84DSrU7oXLREyX82Oq24VDlFuyo8Hbib83v4Z0F2CLPYDvsWzxD1NicO2OSqsqgnZZ0sFwC4VnawcsvA/640?wx_fmt=png&from=appmsg "")  
  
该公司表示，该攻击者使用了定制工具，表现出对间谍活动的明确关注以及对其目标设备的深入了解，这是成熟的国家资助攻击者的标志。  
  
思科表示，它观察到黑客团队部署了两个后门，这些后门共同用于针对目标进行恶意操作，其中包括配置修改、侦察、网络流量捕获/渗透以及潜在的横向移动。  
> 该公司警告称：“思科与受害者和情报合作伙伴合作，发现了一个复杂的攻击链，该攻击链用于植入定制恶意软件并在一小部分客户中执行命令。”  
  
  
思科研究人员表示，网络遥测和情报合作伙伴提供的信息表明，黑客有兴趣刺探微软和其他供应商的网络设备。  
> 思科表示：“无论您的网络设备提供商是谁，现在都是确保设备正确修补、登录到中央安全位置并配置为具有强大的多因素身份验证 (MFA) 的时候了。”  
  
  
**信源：**  
**https://mp.weixin.qq.com/s/pU4AlNI8VyIAlfuOBs2llQ**  
  
****# 因发起网络攻击，  
# 美国悬赏 1000 万美元逮捕四名伊朗公民  
#   
#   
#   
#   
###   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
#   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/jeDQCJpl84DSrU7oXLREyX82Oq24VDlFrX5PpT55G9EbmWcr02YIKPyH4hRLyFt8aElZYpo6HsWzcEeAzoNicPw/640?wx_fmt=jpeg&from=appmsg "")  
  
**标签：勒索软件，钓鱼攻击******  
  
美国财政部外国资产控制办公室 (OFAC) 对四名伊朗国民实施制裁，因为他们参与了针对美国政府、国防承包商和私营公司的网络攻击。OFAC 还制裁了与伊朗伊斯兰革命卫队网络电子司令部 (IRGC-CEC)有关联的两家幌子公司 Mehrsam Andisheh Saz Nik (MASN) 和 Dadeh Afzar Arman (DAA) 。  
  
伊朗伊斯兰革命卫队网络电子司令部（IRGC-CEC）是伊朗政府内负责网络安全和网络战的组织。由于其参与各种网络活动，它被包括美国在内的许多国家视为主要威胁。  
  
这些伊朗国民参与了针对十几家美国公司和政府实体的袭击。他们发起了鱼叉式网络钓鱼和恶意软件攻击。美国司法部和联邦调查局针对这四人在这些网络行动中所扮演的角色提起了起诉书。  
> 美国财政部负责恐怖主义和金融情报的副部长布莱恩·尼尔森 (Brian E. Nelson) 表示：“伊朗恶意网络行为者继续以协调一致的多管齐下的行动针对美国公司和政府实体，旨在破坏我们关键基础设施的稳定并对我们的公民造成伤害。” “美国将继续利用我们的整体政府方法来揭露和破坏这些网络的运营。”  
  
  
伊朗网络行为者坚持通过各种网络活动瞄准美国，包括针对关键基础设施的勒索软件攻击以及针对个人、公司和政府实体的鱼叉式网络钓鱼活动。  
  
这四名伊朗公民是 Hossein Harooni、Reza Kazemifar、Komeil Baradaran Salmani 和 Alireza Shafie Nasab，他们被指控参与利用鱼叉式网络钓鱼和其他黑客技术窃取数十万企业员工账户的恶意软件操作。  
  
Alireza Shafie Nasab 和 Reza Kazemifar Rahman 在 MASN 工作期间针对美国实体。卡泽米法尔参与了针对财政部的袭击。Hosein Mohammad Harooni 使用鱼叉式网络钓鱼和社会工程攻击财政部和其他美国实体。Komeil Baradaran Salmani 与多家 IRGC-CEC 幌子公司合作，参与针对包括财政部在内的多个美国实体的鱼叉式网络钓鱼活动。  
> “由于今天的行动，上述指定人员在美国或由美国人拥有或控制的所有财产和财产权益均被封锁，并且必须向 OFAC 报告。此外，由一名或多名被封锁人员直接或间接、单独或合计拥有 50% 或以上股份的任何实体也将被封锁。  
> 除非获得 OFAC 颁发的一般或特定许可证授权或豁免，否则 OFAC 的法规通常禁止美国人或在美国境内（或过境）进行所有涉及指定或以其他方式被阻止的人员的任何财产或财产权益的交易。”宣读公告。“此外，与受制裁实体和个人进行某些交易或活动的金融机构和其他人员可能会受到制裁或受到执法行动。”  
  
  
这四名男子仍然尚未被美国控制。美国国务院还宣布悬赏 1000 万美元，奖励提供线索逮捕四名伊朗国民的人。  
  
  
**信源：****https://www.secrss.com/articles/65587**  
  
#   
  
资讯来自全球范围内媒体报道  
  
版权归作者所有  
文章内容仅代表作者独立观点  
  
不代表网络盾牌立场  
转载目的在于传递更多信息  
  
如有侵权，请公众号后台联系   
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvpmPPwhn8ph4G0bBhX5W4qQ9LteAHExfMBO0SSIBflErBEkZpYhicyqw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvaZ537GuEvWFB8KtSPrr9BJhHx6z1cRNGZpibKX30Cuic27sWl6bAlEIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvPXlrxoTW9eC948vFoRAB5vic4ChYaE4ibGsJendG8wouZtbeMR0cFTdw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvaZ537GuEvWFB8KtSPrr9BJhHx6z1cRNGZpibKX30Cuic27sWl6bAlEIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一键四连  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicv02Y4KYweCHz4CV1vMg58pTaxHVfG4926EeEYLUpvVKCm8ZT4LZDJxQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvaZ537GuEvWFB8KtSPrr9BJhHx6z1cRNGZpibKX30Cuic27sWl6bAlEIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvymLqu7BQxYguReyu7C86lib1hicrd88uiaCH65Eicm8w1EPo59I5cf6btQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jeDQCJpl84Cml1RJlhy5OECE0lnnZicicvaZ537GuEvWFB8KtSPrr9BJhHx6z1cRNGZpibKX30Cuic27sWl6bAlEIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
