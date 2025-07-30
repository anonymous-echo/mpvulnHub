#  11个严重的 RCE 漏洞影响数千款 IIoT 设备   
 代码卫士   2023-05-17 16:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**作者：Elizabeth Montalbano**  
  
**编译：代码卫士**  
  
****  
**三款工业蜂窝路由器厂商的云管理平台中存在11个漏洞，可导致运营 (OT) 网络易遭远程代码执行攻击，即使该平台未被活跃配置用于云管理。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS69gXj1Xiawtn7dTtuQVhOEwib1MsevesgmDKYJwqyLInf239ZDPBiaMnHPfibf55nsFr8YqrxiaianpcA/640?wx_fmt=png "")  
  
  
Otorio 公司的安全研发团队主管 Eran Jacob 和安全研究员 Roni Gavrilov表示，这些漏洞非常严重，虽然仅影响三家厂商 Sierra Wireless AirLink、Teltonika Networks RUT 和 InHand Networks InRouter的设备，但仍然影响多个行业数千款工业物联网设备和网络。  
  
研究员指出，“由于 IIoT 设备常与互联网以及内部 OT 网络联网，因此攻陷这些设备可绕过常见部署中的所有安全层。同时，这些漏洞也存在通过内置 VPN 向其它网站传播的风险。”  
  
如果攻击者能够直接联系内部 OT 环境，那么也可为物理环境中的用户带来生产和安全风险。  
  
另外，攻击者具有用于利用漏洞的多个向量，包括通过反向 shell 获得根访问权限：攻陷生产网络中的设备便于越权访问并通过根权限进行控制；以及攻陷爱你设备，提取敏感信息并执行各种操作等。  
  
上周，Gavrilov 在2023年亚洲黑帽大会上共享了重要发现和缓解措施。这些漏洞已负责任地披露给厂商和CISA，厂商已采取缓解措施。  
  
  
**0****1**  
  
**问题的根源**  
  
  
工业蜂窝路由器可使多个设备从蜂窝网络连接到互联网。这些路由器通常用于工业设置中如制造厂或油井设备中，而传统的有线互联网连接可能不可用或者不可靠。报告指出，“工业蜂窝路由器和网关已成为 IIoT 场景中最常见的组件。他们提供广泛的连接特性并可在最小修改情况下，无缝集成到现有环境和解决方案中。”  
  
这些设备的厂商通过云平台为客户的 OT 网络提供远程管理、扩展、分析和安全能力。具体而言，研究人员解释称，某些设备中的多个漏洞“与 IIoT 设备和云管理平台之间的连接有关”，而这些连接是默认启用的。  
  
研究人员还提到，“这些漏洞可用于多种场景中，影响已注册和未注册远程管理平台的设备。从本质上来讲，某些设备与云管理平台的默认连接设备中存在安全弱点，而这些弱电可遭利用。”  
  
这些平台的常见连接依赖于机器对机器协议如适用于设备-云通信的 MQTT以及用于用户管理的 web 接口等。MQTT 以发布-订阅模式运营，经纪人负责管理主题，而设备可订阅为接收已发布信息。特定的设备 API 常用于和云平台的初始化通信，而 API 和 Web 接口用于设备管理。  
  
  
**0****2**  
  
**攻击向量**  
  
  
研究人员发现，这种连接的三个重要领域中的多个攻击向量可利用多个严重问题：资产-注册流程、安全配置以及外部 API 和 web 接口。  
  
研究人员表示，“攻击者可通过利用源如 WiGLE 和信息泄露漏洞等攻击特定设施，或者对数千台设备发动大规模攻击，旨在造成更大的影响或获得更多的访问权限。”此外，攻击者可利用这些漏洞干扰运营流程，使在该环境中工作的人员面临风险。  
  
其中一个攻击向量对于勒索团伙具有较高价值，由于设备的内置 VPN 连接，可触及初始接入点以外的站点。这就导致攻击在更广泛的网络中传播，控制中心和SCADA 服务器等。  
  
  
**0****3**  
  
**缓解策略**  
  
  
研究人员为这些设备的 OT 网络管理员和厂商提出了很多缓解策略。OT网络管理员如果并未使用路由器进行云管理，则因禁用任何不用的云特性，阻止设备被接管以及减少攻击面。  
  
同时，在讲设备连接到互联网之前，应当在云平台上自己的账户下注册设备。如此，设立所有权和控制权限，并阻止越权访问权限。另外，管理员可限制从 IIoT 设备到路由器的直接访问权限，因为一旦内置安全特性如 VPN 隧道和防火墙受陷，则无效。  
  
报告提到，“增加单独的防火墙和VPN 层可协助分割和减少用于远程连接的 IIoT 设备遭暴露。”  
  
作为厂商，他们可避免在设备注册和连接建立阶段使用薄弱标识并使用更多“机密”标识的方式，避免将漏洞构建到设备中。他们还应当执行初始凭据设置，以便网络操作人员不会使用默认凭据而引发安全风险。此外，IIoT 的安全要求是唯一的且应当与 IoT 证据分开考虑，因为二者并不能等同。Gavrilov 表示，“这可能涉及按要求降低‘高风险’的特性，以及增加额外的认证、加密、访问控制和监控层。”  
  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[PTC修复多款IIoT 产品中的两个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515804&idx=3&sn=7d29461492a7eda34f8149d7d1ed3ba7&chksm=ea948ff6dde306e0ae9bfa5d97c7b4fc5473ff02f869b56726b0b747122d854826337cbf074a&scene=21#wechat_redirect)  
  
  
[无线IIoT设备中存在38个漏洞，关键基础设施面临风险](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515523&idx=2&sn=f3404ee54f85c9dcbdde1861e22d827f&chksm=ea948ce9dde305ffd33438f09e7d1af126688fd2a6d90cd258f0058a63be408b76949ae69d7f&scene=21#wechat_redirect)  
  
  
[Moxa IIoT 产品有缺陷 导致 ICS 易受远程攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489104&idx=4&sn=763f93957651f81be1c109d3a13ec6d0&chksm=ea97273adde0ae2c9cfe1e0284199892606737d6ac1fe17a9e4ca7de314507df8228cf7eae11&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/ics-ot/severe-rce-bugs-industrial-iot-devices-devices-cyberattack  
  
  
题图：Pexels License  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
