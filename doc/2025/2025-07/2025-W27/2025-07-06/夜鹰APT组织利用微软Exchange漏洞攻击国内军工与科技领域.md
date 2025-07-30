> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTM4OTQ5Mg==&mid=2247636489&idx=4&sn=2133ab4c53798a33591c247a0492d1d0

#  夜鹰APT组织利用微软Exchange漏洞攻击国内军工与科技领域  
freebuf  商密君   2025-07-06 14:00  
  
网络安全研究人员近日披露了一个名为夜鹰（NightEagle，又称APT-Q-95）的未记录威胁组织，该组织利用微软Exchange服务器漏洞实施攻击，其攻击链包含零日漏洞利用，主要针对我国国内的政府、国防和科技部门。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319v1Y0JM0gjq7tocz5gwjtNVTiab9EzMgXyWgnMK9mZTibBgrKUxQj2hkuw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**Part01**  
## 攻击特征与基础设施  
##   
  
据奇安信红雨滴团队报告，该威胁组织自2023年开始活跃，其网络基础设施更换速度极快。相关发现已在2025年7月1日至3日举办的第三届马来西亚国家网络防御与安全展览会（CYDES 2025）上公布。  
  
  
安全厂商在解释"夜鹰"命名缘由时表示：  
"该组织行动速度如鹰，且主要在中国夜间时段活动"。奇安信补充称，该组织主要针对高科技、芯片半导体、量子技术、人工智能和军事领域的实体机构，核心目的是窃取情报。  
  
  
**Part02**  
### 定制化攻击工具分析  
  
  
奇安信表示，调查始于在某客户终端发现定制版的Go语言工具Chisel。该工具被配置为计划任务，每四小时自动启动一次。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vOHnd4jzht8fsjg4WuHjWkj2N5g4eyHmiatF8euHhzM1ia7QWtU8MrI8Q/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
报告指出：攻击者修改了开源内网穿透工具Chisel的源代码，硬编码执行参数，使用指定用户名密码，与指定C&C地址的443端口建立socks连接，并映射到C&C主机的指定端口实现内网穿透功能。  
  
  
**Part03**  
### 零日漏洞利用细节  
  
  
分析发现，木马程序通过.NET加载器投递，该加载器被植入微软Exchange服务器的IIS服务中。进一步分析确认攻击者利用零日漏洞获取machineKey，从而未经授权访问Exchange服务器。  
  
  
报告称：攻击者利用该密钥对Exchange服务器进行反序列化操作，从而在任何符合版本的服务器上植入木马，远程读取任意人员的邮箱数据。  
  
  
奇安信认为，根据攻击活动集中在北京时间晚9点至次日凌晨6点的特征，该威胁组织很可能来自北美地区。微软尚未对  
Exchange服务器漏洞问题发表回复。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzI5NTM4OTQ5Mg==&mid=2247633989&idx=1&sn=cd6647451cec618b20dd28533702603b&scene=21#wechat_redirect)  
  
  
点击购买《2023-2024中国商用密码产业发展报告》  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：  
freebuf  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
