> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQyODI4Ng==&mid=2247497165&idx=3&sn=8535a3b35554e87807cf2bf53a87f4bb

#  夜鹰APT组织利用微软Exchange漏洞攻击国内军工与科技领域  
 网络安全与人工智能研究中心   2025-07-08 01:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibyxtdPv3Xibm2WIxGeGTOHiaeHaXicVpjEoCpdMziceBzFewde58rWGj6FsfNRiaHLOk9hXVLA41Gjk50g/640?wx_fmt=gif&from=appmsg "")  
  
  
网络安全研究人员近日披露了一个名为夜鹰（NightEagle，又称APT-Q-95）的未记录威胁组织，该组织利用微软Exchange服务器漏洞实施攻击，其攻击链包含零日漏洞利用，主要针对我国国内的政府、国防和科技部门。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibyxtdPv3Xibm2WIxGeGTOHiaeVEWm9Op545DDEnt04FBqqI5iaTgUylZdWbbov9vYUfqTHLkN1k3icXFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part01**  
  
## 攻击特征与基础设施  
  
  
##   
  
据奇安信红雨滴团队报告，该威胁组织自2023年开始活跃，其网络基础设施更换速度极快。相关发现已在2025年7月1日至3日举办的第三届马来西亚国家网络防御与安全展览会（CYDES 2025）上公布。  
  
  
安全厂商在解释"夜鹰"命名缘由时表示：  
"该组织行动速度如鹰，且主要在中国夜间时段活动"。奇安信补充称，该组织主要针对高科技、芯片半导体、量子技术、人工智能和军事领域的实体机构，核心目的是窃取情报。  
  
  
**Part02**  
  
### 定制化攻击工具分析  
  
  
奇安信表示，调查始于在某客户终端发现定制版的Go语言工具Chisel。该工具被配置为计划任务，每四小时自动启动一次。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibyxtdPv3Xibm2WIxGeGTOHiaeiaiafv2Bu1RrFKVNbUibsygJLheGw4ITJ44rQwSK3rkdfCSHr21WG1esg/640?wx_fmt=jpeg&from=appmsg "")  
  
报告指出：攻击者修改了开源内网穿透工具Chisel的源代码，硬编码执行参数，使用指定用户名密码，与指定C&C地址的443端口建立socks连接，并映射到C&C主机的指定端口实现内网穿透功能。  
  
  
**Part03**  
  
### 零日漏洞利用细节  
  
  
分析发现，木马程序通过.NET加载器投递，该加载器被植入微软Exchange服务器的IIS服务中。进一步分析确认攻击者利用零日漏洞获取machineKey，从而未经授权访问Exchange服务器。  
  
  
报告称：攻击者利用该密钥对Exchange服务器进行反序列化操作，从而在任何符合版本的服务器上植入木马，远程读取任意人员的邮箱数据。  
  
  
奇安信认为，根据攻击活动集中在北京时间晚9点至次日凌晨6点的特征，该威胁组织很可能来自北美地区。微软尚未对  
Exchange服务器漏洞问题发表回复。  
  
  
**参考来源：**  
  
NightEagle APT Exploits Microsoft Exchange Flaw to Target China's Military and Tech Sectors  
  
https://thehackernews.com/2025/07/nighteagle-apt-exploits-microsoft.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibyxtdPv3Xibm2WIxGeGTOHiaecJHVbBD6xboUBex9vuwhVuKiamv1jxHesepNyCUBibdxewPmekCkZItw/640?wx_fmt=png&from=appmsg "")  
  
编辑：席沐沂  
  
审核：秦川原  
  
来源：FreeBuf  
  
###   
###   
  
  
  
  
  
  
