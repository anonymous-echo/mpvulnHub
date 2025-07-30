#  知名开源监控系统Zabbix存在SQL 注入漏洞   
天唯科技  天唯信息安全   2024-12-04 02:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
Zabbix 存在 SQL 注入漏洞（CVE-2024-42327），该漏洞是由于在 Zabbix前端的CUser类中的addRelatedObjects函数未对输入数据进行充分验证和转义，导致具有API访问权限的恶意用户可以通过user.get API传递特制输入触发SQL注入攻击，进而利用该漏洞实现权限提升或访问敏感数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljNjbcFCaXKEbVibCkASomibXTTdDI4rumBvMAvC7mNzPumFiaf15Niag56ljI7fmLIEJficicUWItYiaAcw/640?wx_fmt=jpeg&from=appmsg "")  
  
Zabbix是一个基于WEB界面的提供分布式系统监视以及网络监视功能的企业级开源监控解决方案，可以用来监控服务器、硬件、网络等。  
  
该漏洞位于user.get API端点，任何具有API访问权限的非管理员用户均可利用，包括默认的“用户”角色。利用这一漏洞，攻击者可以通过操控特定的API调用，注入恶意SQL代码，从而获得未授权的访问和控制权限，进而完全控制Zabbix实例，导致敏感监控数据和连接系统的泄露。  
  
Qualys公司对于该漏洞进行分析，指出利用这个漏洞可能允许攻击者提升权限并获得对易受攻击的Zabbix服务器的完全控制，且目前已经发现，有超过83000个暴露在互联网上的Zabbix服务器。  
  
漏洞具体信息如下：  
### 漏洞等级  
  
**高危**  
### 受影响版本  
  
**目前受影响的Zabbix版本：**  
  
**6.0.0 <= Zabbix < 6.0.32rc1**  
  
**6.4.0 <= Zabbix < 6.4.17rc1**  
  
**Zabbix 7.0.0**  
### 修复方案  
  
目前官方已发布新版本修复该漏洞，建议受影响用户升级到Zabbix 6.0.32rc1、Zabbix 6.4.17rc1、Zabbix 7.0.1rc1或更高版本。官网地址：https://www.zabbix.com/download  
  
尽管关于CVE-2024-42327的咨询仅在上周发布，但包含该问题补丁的版本6.0.32rc1、6.4.17rc1和7.0.1rc1已于7月发布。这些修补版本还解决了另外一个漏洞，编号为CVE-2024-36466（CVSS评分为8.8）。该漏洞存在认证绕过问题，可能允许攻击者签署伪造的zbx_session cookie并以管理员权限登录。  
  
Zabbix版本7.0.1rc1还修复了CVE-2024-36462，这是一个不受控制的资源消耗漏洞，可能允许攻击者造成拒绝服务（DoS）状态。目前没有发现该漏洞被公开利用的情况，强烈建议用户尽快安全最新版本，以修复上述漏洞。  
  
参考来源：https://www.securityweek.com/critical-vulnerability-found-in-zabbix-network-monitoring-tool/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNbU68NXCNH8sw9R1wBYiaT6icvH7moZbnkDB7UPWcP57YnEr5sDNDh6pssbCmuxvzQERZeMhN6Dknw/640?wx_fmt=png "")  
  
  
天唯科技专注于大型组织信息安全领域及IT基础设施解决方案的规划、建设与持续运维服务。帮助客户提高IT基础设施及信息安全管控水平和安全运营能力，使客户在激烈的市场环境中保持竞争力。  
  
我们一直秉承“精兵强将，专业专注”的发展理念。  
先后在江门、深圳成立分公司，在武汉、长沙成立办事处以及成立广州的服务支撑中心。公司已获得高新技术企业认证、已通过IS09001、IS027001、CCRC信息安全集成服务、CCRC信息安全风险评估、CCRC信息安全应急处理等认证。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PZibWfCgzicQNRytkPMNOKYRW452LxR5Ez5Wee8X6KlbhoUMt9XyhhbRxHafKcCLWJic3ib0umJiaH3fl6sOx8KMBiaQ/640?wx_fmt=png "盾牌单图.png")  
  
**END**  
  
  
  
**往期推荐:**  
  
  
  
  
  
[网络无边 安全有界](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502867&idx=1&sn=3d2a566b9b34195eea0f3e424eaadf41&scene=21#wechat_redirect)  
  
  
  
[国家安全部提醒：警惕开源信息成为泄密源头](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502867&idx=2&sn=1540f5f8add1104f2df407e80f1e6aed&scene=21#wechat_redirect)  
  
  
  
[首次曝光！间谍软件厂商为政府客户执行网络攻击](https://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247502826&idx=1&sn=32f9f272ef2c199ddc5833a0a1392d15&scene=21#wechat_redirect)  
  
  
  
**征文通道:**  
  
  
  
  
  
[发钱！征文！让真诚的分享更有价值](http://mp.weixin.qq.com/s?__biz=MzkzMjE5MTY5NQ==&mid=2247490310&idx=1&sn=db4b524d1d9f5aabb4af2184dd831de3&chksm=c25ed7a6f5295eb053d3f90e2dc8cd22a2d8ce1a62561ffa62966340ee563734cd4fd32045f3&scene=21#wechat_redirect)  
  
  
