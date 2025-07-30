#  Gayfemboy：一个利用四信工业路由0DAY传播的僵尸网络   
原创 奇安信X实验室  奇安信XLab   2025-01-07 08:48  
  
#   
# 概述  
  
无数脚本小子怀揣着发财梦，拿着 Mirai 的源码兴高采烈地杀入 DDoS 黑产行业，幻想着靠僵尸网络大赚一笔。现实是残酷的，这些人来时满怀雄心，去时却灰头土脸，只给安全社区留下一个又一个只能活跃 3–4 天的 Mirai 变种。然而，今天的主角Gayfemboy是一个例外。  
  
Gayfemboy 僵尸网络首次于 2024 年 2 月初被 XLab 捕获，并持续活跃至今。它的早期版本并不起眼，仅仅是一个使用 UPX 加壳的 Mirai 派生版本，毫无新意。然而，其背后的开发者显然不甘平庸，随后展开了一场激进的迭代进化之旅。他们从修改上线报文入手，开始尝试 UPX 变形壳，积极整合 Nday 漏洞，甚至自行挖掘 0day 漏洞，持续扩大 Gayfemboy 的感染规模。  
  
到了 2024 年 11 月初，Gayfemboy 再次进化，开始利用 四信工业路由器 0day 漏洞 以及 Neterbit 路由器 和 Vimar 智能家居设备 的未知漏洞传播样本。这一发现让我们决定对该僵尸网络进行更深入的分析，于是注册了部分 C2 域名用以观察被感染的设备，以及度量僵尸网络的规模。结果显示 Gayfemboy 拥有40多个上线分组，日活跃节点已经超过 1.5 万。有意思的是，当它发现域名被我们注册后，马上对我们抢注的域名展开了DDoS攻击，相当睚眦必报。  
  
依托于XLab大网威胁感知系统的能力，回顾Gayfemboy的演化历程，我们见证了它从一个普通的Mirai变种，一步步进化为今天拥有0day利用能力，攻击颇为凶猛，具有自身特色的大型僵尸网络。  
- 2024年02月12日，XLAB首次发现Gayfemboy样本，使用普通upx壳  
  
- 2024年4月15日，upx幻数修改为YTS\x99  
，开始使用gayfemboy  
上线报文，  
  
- 2024年6月初，upx幻数修改为1wom  
，bot代码基本固定，偶尔新增几个C2域名  
  
- 2024年8月底，样本硬编码6个C2，后3个C2是未注册的状态  
  
- 2024年11月09日，观察到Gayfemboy开始使用四信工业路由0day漏洞传播样本，样本运行参数为faith2  
  
- 2024年11月17日，我们注册了Gayfemboy样本中部分未注册的域名，用来观察Gayfemboy感染的设备和僵尸网络规模。  
  
- 2024年11月23日，Gayfemboy的所有者发现我们注册了他的CC域名，开始定期对我们注册的域名发起DDoS攻击。  
  
- 2024年12月27日，VulnCheck公开了四信工业路由器 0day的漏洞信息。  
  
#   
# 漏洞利用  
  
Gayfemboy使用20多个漏洞和Telnet弱口令传播样本，其中包括四信工业路由0day漏洞(当前漏洞已经公布，CVE编号为：CVE-2024-12856)，部分未知漏洞涉及Neterbit和vimar设备（这部分因为漏洞未公开，为防止漏洞被滥用，本文暂且按下不表）。Gayfemboy利用的主要漏洞如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrYO06iaOOeNmKo26dzqKGA6BhegZP2uaUcMv9dyGE5R3WQfoGx8rf2Ww/640?wx_fmt=png&from=appmsg "")  
# 感染规模  
## BOT数量趋势  
  
根据我们收集到的数据看，Gayfemboy僵尸网络的日活Bot IP数量在1.5万左右。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmribTLtzFW7LnQbYpOFQ4MYN6OH6WPNp9uF65vGw45DhCibeWibdMTibV1tQ/640?wx_fmt=png&from=appmsg "")  
  
主要感染分布在中国、美国、伊朗、俄罗斯、土耳其  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrQGsMFR5DibroAJPermznRXzmuiaOZ3x8hLh13hxwcpfO2hQ4J03RbJEg/640?wx_fmt=png&from=appmsg "")  
  
**主要感染的设备**  
  
Gayfemboy Bot连接CC时携带一个分组信息，这些分组信息是为了标识并组织被感染的设备，以便攻击者更有效地管理和控制庞大的僵尸网络。这个分组信息通常包含一些关键的标识符，例如设备的操作系统类型、或者其他识别信息。很多攻击者也喜欢用感染设备的方式来作为标识。Gayfemboy的上线分组信息是设备信息。感染的主要设备如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmr3p17evicxgLumUT2ib1geVK3m2y3KUF6gEWVFPbbH1ORP8KVpdBUJK8g/640?wx_fmt=png&from=appmsg "")  
#   
# DDoS 分析  
## 攻击目标  
##   
  
Gayfemboy僵尸网络的发起攻击从2024年02月至今断断续的一直有，其中去年10月和11月份攻击目标最多。每天攻击上百个目标。攻击目标遍布全球，分布在各个行业，主要攻击目标分布在中国、美国、德国、英国、新加坡等地区。攻击目标趋势如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrz1Nvrdbm5F9pGiadGydvYlgBJ8UgNFlazHdhrgAjB65tLwQrcGzqibaw/640?wx_fmt=png&from=appmsg "")  
  
攻击目标地理位置分布：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrRTac1aSehglJOibRtO3yaUJMDvoDuchXtDicyEZszvSNEPnstZ2oq0qg/640?wx_fmt=png&from=appmsg "")  
##   
##   
## 攻击能力  
  
我们将抢注的Gayfemboy域名解析到了云厂商的VPS。Gayfemboy的所有者发现后开始定期对我们注册的域名发起DDoS攻击，每次攻击时长10到30秒。云厂商发现我们的VPS被攻击后会立即将我们的VPS流量黑洞路由24小时以上，这将导致我们的VPS无法提供服务，也无法访问(我们的VPS还没有被Gayfemboy打死，就被云厂商先干死了，云厂商服务策略如此)。一旦VPS服务恢复，Gayfemboy又攻过来了。因为我们没有购买抗DDoS服务，最终选择停止解析Gayfemboy的域名。部分攻击指令记录如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrQLYWsr8fV4gUXicxa0icAlPKbxTfDdwcoImhaS9xhm1HRnywmRXW04pQ/640?wx_fmt=png&from=appmsg "")  
  
根据云厂商提供的流量监控服务可以看到Gayfemboy攻击流量可能在百G  
左右。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmr6Kjw3J2ia8AwLFZkf4UaGe3WJ06lTb97AIBXxsj7dwcKnufNUZEcRSA/640?wx_fmt=png&from=appmsg "")  
#   
# 样本分析  
  
该家族使用魔改UPX壳，早期使用的幻数为"YTS\x99"，自2024年6月之后开始使用独特幻数"1wom"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrMAiazPOjdIruRq1Oe0ap4C2Et5xoRo4ZUYNw0VqZgKVMUnItTF4JYiag/640?wx_fmt=png&from=appmsg "")  
  
  
在代码方面基于Mirai进行修改：  
- 删除Mirai字符串表，使用明文字符串  
  
- 添加隐藏pid函数  
  
- 修改上线包为"gayfemboy"  
  
- 添加新的指令功能  
  
为增加分析难度、保护程序，botnet开发者往往会对字符串进行加密，但该开发者似乎不重视字符串的保护，字符串全部使用明文，样本在运行后会输出"we gone now\n"，该特征从发现样本开始一直没有改变  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrNYFhbLXmgxKWBTPVqAfRnRicFcNIX10jDgrJOQa5xogE7yQdtBTO8TA/640?wx_fmt=png&from=appmsg "")  
  
为隐藏恶意进程，样本启动后会尝试从根目录开始查找可写入的目录，并尝试写入随机的2032字节文件test_write作为测试，成功后会删除该文件，在遇到以下目录时会跳过  
```
/proc/sys/dev/fd/boot
```  
  
当找到可写入目录时，尝试通过挂载该目录到/proc/<pid>上使该进程在/proc文件系统中不可见，以此隐藏指定的PID。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmricBwd3kJZcKQickEDpf0x7Zztnrl4vPzcND1Ac8E3ibNHhH46J5EZrpxQ/640?wx_fmt=png&from=appmsg "")  
  
在网络协议方面，保留了Mirai的指令格式，修改上线包并添加新的指令功能：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrGDWKblxcr4IjqI87NaPZlicDZdG9IQicFDvQAdL3bCqNibtYWlgJ5ldKQ/640?wx_fmt=png&from=appmsg "")  
  
常规的DDoS相关指令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrQ9VMyvnAq6F3jcrAOm4eAyJ4cUiaUwnGjNJcmVic2IphFOJ2aysAjk9Q/640?wx_fmt=png&from=appmsg "")  
  
  
当收到自更新指令时，会从指令中获取下载服务器和botid，默认使用meowware.ddns.net作为下载服务器，样本中硬编码了多个下载相关的指令格式字符串  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmribUEWIA2P5eVj7HUH1hXWJibgoPaSpIT8xsKlV6oDkEFKfWpV5nTPd9w/640?wx_fmt=png&from=appmsg "")  
  
作用是使用wget从固定目录chefrvmanabat下载文件，以botid为参数执行。  
  
当收到扫描指令时，从指令中解析多个自定义参数，如扫描端口、上报服务器、上报端口、验证返回包等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/I28micxvFPbhtpUqU3DGozgNWd8QiaUrmrJvBAmsg3FxUz0L4YDtAm4dsenribn2k5U5CuzovDaTAym8TdDrmt40Q/640?wx_fmt=png&from=appmsg "")  
#   
#   
# 总结  
  
DDoS（分布式拒绝服务）作为一种高度可重复使用且成本相对较低的网络攻击武器，因其能够通过分布式僵尸网络、恶意工具或放大技术，瞬间发起大规模流量攻击，对目标网络资源进行耗尽、瘫痪或服务中断，已成为网络攻击中最常见和最具有破坏力的手段之一。其攻击模式多样化、攻击路径隐蔽性强，并能通过不断变化的策略与技术手段，针对不同的行业和系统实施精准打击，从而对企业、政府机构和个人用户造成严重威胁。企事业和个人应从不同层面制定完善的防御策略降低DDoS攻击的风险，提升系统的整体抗压能力。  
  
  
