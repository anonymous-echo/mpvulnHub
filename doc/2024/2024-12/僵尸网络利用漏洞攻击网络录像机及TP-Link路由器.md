#  僵尸网络利用漏洞攻击网络录像机及TP-Link路由器   
天唯科技  天唯信息安全   2024-12-26 01:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
****  
据BleepingComputer消息，一个基于Mirai的新型僵尸网络正在积极利用DigiEver网络录像机中的一个远程代码执行漏洞，该漏洞尚未获得编号，也暂无修复补丁。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhApEOE1lUNibicgVFDsHUoLiag1vTX8CtucI9ryepcgd9sN3ldAD4RIZccBfNZwtr3Ya8gGzg6R879Q/640?wx_fmt=jpeg&from=appmsg "")  
  
Akamai 研究人员观察到，该僵尸网络于 11 月中旬开始利用该漏洞，但证据表明该活动至少自 9 月以来就一直活跃。  
  
除了 DigiEver 漏洞外，新的 Mirai 恶意软件变体还分别利用CVE-2023-1389和 CVE-2018-17532 漏洞针对未打安全补丁的 TP-Link 和 Teltonika RUT9XX 路由器。  
  
研究人员称，被用来攻击 DigiEver NVR 的远程代码执行 （RCE） 漏洞源自“/cgi-bin/cgi_main. cgi”URI，该URI 未正确验证用户输入，允许未经身份验证的远程攻击者通过某些参数（如 HTTP POST 请求中的 ntp 字段）注入 "curl "和 "chmod "等命令。  
  
通过命令注入，攻击者从外部服务器获取恶意软件二进制文件，并将设备加入其僵尸网络。设备一旦被入侵，就会被用来进行分布式拒绝服务（DDoS）攻击，或利用漏洞集和凭证列表扩散到其他设备。  
  
Akamai表示，新Mirai变种的显著特点是使用了XOR和ChaCha20加密技术，并以x86、ARM和MIPS等多种系统架构为目标，这不同于许多基于 Mirai 的僵尸网络仍然依赖于原始的字符串混淆逻辑，这种逻辑来自于原始 Mirai 恶意软件源代码发布时包含的回收代码。虽然采用复杂的解密方法并不新颖，但这表明基于Mirai的僵尸网络的战术、技术和程序在不断发展。  
  
据悉，早在去年罗马尼亚布加勒斯特举行的 DefCamp 安全会议上，TXOne 研究员 Ta-Lun Yen就曾揭露过该漏洞，该问题当时影响了多个 DVR 设备。  
  
参考来源：New botnet exploits vulnerabilities in NVRs, TP-Link routers  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[立即更新！Adobe警告ColdFusion严重漏洞PoC](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503274&idx=1&sn=eedb40242f561ac4e1a6fdbe1ab26061&scene=21#wechat_redirect)  
  
  
  
[关于针对我国用户的“银狐”木马病毒再次出现新变种并更新传播手法的预警报告](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503274&idx=2&sn=29c0ac615b5e3713bfdb126987c928e7&scene=21#wechat_redirect)  
  
  
  
[Diicot 威胁组织利用高级恶意软件攻击 Linux](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247503244&idx=1&sn=f7fa40e921872107d66cf254b7380a2e&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
