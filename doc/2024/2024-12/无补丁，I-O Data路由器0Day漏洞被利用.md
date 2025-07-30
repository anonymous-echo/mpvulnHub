#  无补丁，I-O Data路由器0Day漏洞被利用   
天唯科技  天唯信息安全   2024-12-09 03:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
日本计算机紧急响应小组（CERT）警告称 ，黑客正在利用I-O Data路由器设备中的零日漏洞来修改设备设置、执行命令，甚至关闭防火墙。  
  
  
I-O Data在其网站上发布的安全公告中承认确实存在三个零日漏洞，但目前暂无完整的修复补丁，预计将在2024年12月18日发布，因此在此之前用户将面临比较严重的风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38G1nYUFhMulWK7EEiadWOtSy0Dvo5PEJUw3eHyJktvEO0cEOdhoYva6vuZy6s8JP9v3aEDKau4ZPQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
上述三个零日漏洞在2024年11月13日被发现，包括信息泄露、远程任意操作系统命令执行和导致防火墙禁用的漏洞。  
  
  
具体如下：  
- CVE-2024-45841：敏感资源上的不当权限配置，导致低权限用户可以访问关键文件。  
  
- CVE-2024-47133：认证的管理员用户可以在设备上注入并执行任意操作系统命令，利用配置管理中的输入验证不充分漏洞。  
  
- CVE-2024-52464：固件中的未记录特性或后门可导致远程攻击者在无需认证的情况下，关闭设备防火墙并修改设置。  
  
**受影响的设备：**  
这些漏洞影响UD-LT1和UD-LT1/EX设备，前者是为多功能连接解决方案设计的混合LTE路由器，而后者是工业级版本。  
  
  
最新可用的固件版本v2.1.9仅解决了CVE-2024-52564漏洞，I-O Data表示其他两个漏洞的修复将在计划于2024年12月18日发布的v2.2.0版本中提供。比较糟糕的消息是，已经有客户因为这些漏洞而遭到黑客攻击。  
  
  
I-O Data安全公告指出，“已收到使用混合LTE路由器UD-LT1和UD-LT1/EX的客户的咨询，这些客户报告了来自外部来源的潜在未经授权访问。”  
  
  
在安全更新发布之前，I-O Data 建议用户实施以下缓解措施：  
  
- 禁用所有互联网连接方式的远程管理功能，包括WAN端口、调制解调器和VPN设置。  
  
- 仅限VPN连接的网络访问，以防止未经授权的外部访问。  
  
- 将默认的“访客”用户的密码更改为超过10个字符的更复杂的密码。  
  
- 定期监控和验证设备设置，以尽早检测未经授权的更改，并在检测到泄露时将设备重置为出厂默认设置并重新配置。  
  
不过国内的企业用户不需要太过担心，因为I-O DATA UD-LT1和UD-LT1/EX LTE路由器主要在日本市场销售，旨在支持NTT Docomo和KDDI等多个运营商，并兼容该国的主要MVNO SIM卡。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[威努特工控主机卫士：全面守护关基设施的“中枢神经”](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502992&idx=1&sn=3b8956abd884d299ef2f29e6878643e7&scene=21#wechat_redirect)  
  
  
  
[中共中央办公厅 国务院办公厅关于推进新型城市基础设施建设打造韧性城市的意见](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502992&idx=2&sn=fbd24d4f8353a73c55e431b9efd4e8b2&scene=21#wechat_redirect)  
  
  
  
[公司系统遭到攻击反而被处罚！原因是……](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502992&idx=3&sn=f613eafd5fef04e8a6865a3c88e14f2b&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
  
  
