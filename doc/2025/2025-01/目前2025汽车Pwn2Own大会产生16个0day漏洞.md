#  目前2025汽车Pwn2Own大会产生16个0day漏洞   
 独眼情报   2025-01-23 03:19  
  
在东京大展览馆举办的2025汽车Pwn2Own大会今天开幕，展示了汽车网络安全研究的前沿技术。  
  
首日，白帽黑客在车载信息娱乐系统（IVI）、电动车充电桩和操作系统中成功利用了16个此前未知的漏洞。大会向参与者颁发了高达382,750美元的奖金。  
# 第一天的重要亮点  
  
本次比赛呈现出成功、重复和失败并存的情况。以下是值得关注的成就：  
- **PCAutomotive**利用栈缓冲区溢出漏洞攻击Alpine IVI系统，赢得20,000美元和两个Master of Pwn积分。  
  
- **Viettel网络安全团队**成功使用操作系统命令注入漏洞攻击Kenwood IVI系统，获得20,000美元和两个积分。  
  
- **ANHTUD的Cong Thanh和Nam Dung**利用整数溢出漏洞在Sony XAV-AX8500 IVI系统上执行代码，赢得20,000美元和两个积分。  
  
- **Summoning Team的Sina Kheirkhah**通过三个漏洞组合攻击Phoenix Contact CHARX SEC-3150电动车充电桩。尽管有一个漏洞之前已被披露，他仍获得41,750美元和4.25积分。  
  
- **Synacktiv**结合栈缓冲区溢出和已知的OCPP漏洞，成功操控ChargePoint充电桩，赢得47,500美元和4.75积分。  
  
最出色的表现来自PHP Hooligans，他们利用堆缓冲区溢出漏洞攻击Autel充电桩，获得50,000美元和五个Master of Pwn积分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTaSia36B3CsibxluGiaOeQ9uLLpmFj5zjkFiaU2PibVVYLj8pHTpSlwkDQoHO2SK8PtScUtK3SPvBZRRA/640?wx_fmt=png&from=appmsg "")  
  
Autel 充电桩  
  
同样令人印象深刻的是Sina Kheirkhah，他后来利用Ubiquiti充电桩中的硬编码加密密钥漏洞，再次获得50,000美元和五个积分。  
  
fuzzware.io团队也取得了成功，他们通过开放端口访问Autel MaxiCharger并利用栈缓冲区溢出漏洞，赢得25,000美元和五个积分。  
  
Bug重复是一个常见现象，多个团队针对相同漏洞：  
- SK Shieldus在攻击去年比赛中Alpine IVI的未修复操作系统命令注入漏洞时遇到重复，仅获得5,000美元和一个积分。  
  
- STEALIEN的Bongeun Koo同样在Alpine IVI上遇到重复，但仍获得5,000美元。  
  
尽管有些尝试未能成功，如Riccardo Mori（Quarkslab）和Sina Kheirkhah在某些目标上的失败尝试，但首日仍充满激情。  
# 积分榜更新  
- fuzzware.io团队凭借多个成功的漏洞利用，目前领跑Master of Pwn比赛。  
  
- 紧随其后的是**Sina Kheirkhah**，他共赢得91,750美元奖金和9.25积分。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTaSia36B3CsibxluGiaOeQ9uLmiadDADugrRKZwvlhcwcZ7qbzJ6CHVDzY0yo5UdIEfcLrw6cicOnScGg/640?wx_fmt=jpeg&from=appmsg "")  
  
排行榜  
  
2025汽车Pwn2Own大会将持续至1月24日，预计还将有更多漏洞被发现。本次大会凸显了随着软件定义汽车日益成为现代交通不可或缺的一部分，解决网络安全风险的重要性。  
# 关于汽车安全的技术文章  
- https://securelist.com/mercedes-benz-head-unit-security-research/115218/ 梅赛德斯-奔驰主机安全研究报告  
  
- https://keenlab.tencent.com/en/whitepapers/Mercedes_Benz_Security_Research_Report_Final.pdf 腾讯科恩实验室关于奔驰 MBUX 内部结构和理解系统架构研究报告  
  
  
  
  
