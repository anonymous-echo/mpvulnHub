> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583172&idx=2&sn=ba838828e94a76da83b0d79076a0969e

#  DanaBleed新漏洞使 DanaBot恶意软件即服务平台浮出水面  
胡金鱼  嘶吼专业版   2025-06-20 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
在2022年6月更新的DanaBot恶意软件操作中引入的最新漏洞，导致其在最近的执法行动中被识别并拆解了他们的操作。  
  
DanaBot是一个从2018年到2025年活跃的恶意软件即服务（MaaS）平台，用于银行欺诈、凭证盗窃、远程访问和分布式拒绝服务（DDoS）攻击。  
  
Zscaler的ThreatLabz研究人员发现了这个被称为“DanaBleed”的漏洞，他们解释说，内存泄漏使他们能够深入了解恶意软件的内部操作和幕后黑手。  
  
利用该漏洞收集有关网络犯罪分子的宝贵情报，一项名为Operation Endgame的国际执法行动使DanaBot基础设施下线，并起诉了该威胁组织的16名成员。  
# DanaBleed漏洞  
  
DanaBleed漏洞是在2022年6月随DataBot 2380版本引入的，该版本新增了一个命令和控制（C2）协议。  
  
新协议逻辑中的一个弱点是生成C2服务器对客户机的响应的机制，该机制应该包含随机生成的填充字节，但没有为这些字节初始化新分配的内存。  
  
Zscaler研究人员收集并分析了大量C2响应，由于内存泄漏错误，这些响应包含来自服务器内存的剩余数据片段。  
  
这次暴露类似于2014年发现的HeartBleed问题，影响了无处不在的OpenSSL软件。随着时间的推移，DanaBleed向研究人员提供了大量私人数据，包括：  
  
**·**  
威胁参与者详细信息（用户名、IP地址）  
  
**·**  
后端基础设施（C2服务器ip /域）  
  
**·**  
受害者数据（IP地址、凭据、泄露信息）  
  
**·**  
恶意软件的更新日志  
  
**·**  
私有密码密钥  
  
**·**  
SQL查询和调试日志  
  
**·**  
C2控制面板的HTML和网页界面片段  
  
在三年多的时间里，DanaBot一直以一种受攻击的模式运行，而其开发人员或客户却没有意识到他们被暴露给了安全研究人员。这使得当执法部门收集到足够的数据时便能一击即中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iciaWUvGohJibw706iaa6WGY20M15gFV2UdngI7jM0icTKZfeSfCsSADT1fFaCeXFGFKlYPe4An2VZJnw/640?wx_fmt=png&from=appmsg "")  
  
C2服务器响应中泄露的HTML数据  
  
虽然DanaBot在俄罗斯的核心团队只是被起诉而没有被逮捕，但关键的C2服务器、650个域名和近400万美元的加密货币被扣押已经有效地消除了目前的威胁。即使威胁者在未来试图重返网络犯罪活动，但其黑客社区信任度的下降也将是他们面临的一个重大障碍。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/danabot-malware-operators-exposed-via-c2-bug-added-in-2022/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iciaWUvGohJibw706iaa6WGY20RueSCglsHcBuSreVIPSCbJU8dVquqnwgj6kiaXT1Iap6uKibbvx4lsDQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2iciaWUvGohJibw706iaa6WGY20qfyxOKpo1x8YTXa1AkAnu9nlkV3jVN8HfPFmJM3g4WEUk4Glib3WCMw/640?wx_fmt=png&from=appmsg "")  
  
  
