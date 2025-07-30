#  Gayfemboy 僵尸网络瞄准 Four-Faith 路由器漏洞   
鹏鹏同学  黑猫安全   2025-01-09 23:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicu2HNRPyaqf04vvicNicnh8ouO6Kl2V5bfs760pDWvoKfondDNZA5p08yo104dyWntx73QTODxVGDg/640?wx_fmt=png&from=appmsg "")  
  
Gayfemboy 僵尸网络最早在2024年2月被发现，它借鉴了基本的Mirai变种代码，并且现在集成了N-day和0-day漏洞利用。到2024年11月，Gayfemboy利用了Four-Faith工业路由器和Neterbit路由器以及Vimar智能家居设备中的0-day漏洞，每天有超过15,000个活跃节点。该僵尸网络的操作者还对追踪它的研究人员发动了DDoS攻击。QiAnXin XLab的专家观察到Gayfemboy通过利用超过20个漏洞来传播其僵尸程序，他们还尝试利用Telnet弱口令。研究人员发现，攻击者针对Four-Faith工业路由器中的零日漏洞CVE-2024-12856，以及影响Neterbit和Vimar设备的几个未知漏洞。  
  
Gayfemboy利用了各种漏洞，包括DVR、路由器和安全设备中的CVE-2013-3307、CVE-2021-35394、CVE-2024-8957等。Gayfemboy僵尸网络的大多数感染发生在中国、美国、伊朗、俄罗斯和土耳其。  
  
当Gayfemboy僵尸程序连接到C2时，它们携带用于识别和组织感染设备的分组信息，使攻击者能够有效地管理和控制庞大的僵尸网络。这些分组信息通常包括关键标识符，例如设备的操作系统类型或其他标识细节。  
  
QiAnXin XLab发布的报告中写道。“许多攻击者也喜欢使用感染方法作为标识符。Gayfemboy的分组信息基于设备细节。主要感染的设备如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEceicu2HNRPyaqf04vvicNicnh8oWZkzyMdBRyVlAKpDDLunPVSS9plK4BTYuFWYG4BCESB9IcRnxC5QlA/640?wx_fmt=png&from=appmsg "")  
  
自2024年2月以来，Gayfemboy僵尸网络一直在对全球数百个目标发动DDoS攻击，活动在十月和十一月达到高峰。主要目标包括中国、美国、德国和英国。该僵尸网络对注册用于分析的域名发动了持续10至30秒的DDoS攻击，针对的是云服务提供商托管的VPS。攻击导致VPS流量被黑洞处理超过24小时。由于没有DDoS保护，团队停止解析这些域名。流量峰值达到100GB，根据提供商的估计。  
  
该僵尸网络基于Mirai，代码分析显示它包含明文字符串和一个自定义的“gayfemboy”注册数据包。作者添加了新的命令和一个PID隐藏功能。尽管有所演变，其明文字符串和未改变的输出消息“we gone now”突显了保护措施的松懈。  
  
“DDoS（分布式拒绝服务）是一种高度可重用且相对低成本的网络攻击武器。它可以利用分布式僵尸网络、恶意工具或放大技术，瞬间发动大规模流量攻击，耗尽、禁用或中断目标网络的资源。因此，DDoS已成为最常见和最具破坏性的网络攻击形式之一。”包含妥协指标（IoCs）的报告总结道。“其攻击模式多样，攻击路径高度隐蔽，并可以采用不断演变的策略和技术，对各种行业和系统进行精确打击，对企业、政府组织和个人用户构成重大威胁。”  
  
  
